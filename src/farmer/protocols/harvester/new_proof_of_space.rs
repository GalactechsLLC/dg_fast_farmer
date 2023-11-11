use crate::farmer::protocols::harvester::respond_signatures::RespondSignaturesHandler;
use crate::farmer::{FarmerIdentifier, FarmerSharedState};
use crate::harvesters::{Harvester, Harvesters, ProofHandler, SignatureHandler};
use crate::HEADERS;
use async_trait::async_trait;
use blst::min_pk::{AggregateSignature, PublicKey, Signature};
use blst::BLST_ERROR;
use dg_xch_clients::api::pool::PoolClient;
use dg_xch_clients::protocols::farmer::NewSignagePoint;
use dg_xch_clients::protocols::harvester::{NewProofOfSpace, RequestSignatures, RespondSignatures};
use dg_xch_clients::protocols::pool::{
    get_current_authentication_token, PoolErrorCode, PostPartialPayload, PostPartialRequest,
};
use dg_xch_core::blockchain::proof_of_space::{generate_plot_public_key, generate_taproot_sk};
use dg_xch_core::blockchain::sized_bytes::{Bytes32, SizedBytes};
use dg_xch_core::clvm::bls_bindings::{sign, sign_prepend, AUG_SCHEME_DST};
use dg_xch_core::consensus::constants::ConsensusConstants;
use dg_xch_core::consensus::pot_iterations::{
    calculate_iterations_quality, calculate_sp_interval_iters,
};
use dg_xch_pos::verify_and_get_quality_string;
use dg_xch_serialize::{hash_256, ChiaSerialize};
use log::{error, info, warn};
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;
use uuid::Uuid;

pub struct NewProofOfSpaceHandle<T: PoolClient + Sized + Sync + Send + 'static> {
    pub pool_client: Arc<T>,
    pub shared_state: Arc<FarmerSharedState>,
    pub harvester_id: Uuid,
    pub harvesters: Arc<HashMap<Uuid, Arc<Harvesters>>>,
    pub constants: &'static ConsensusConstants,
}

#[async_trait]
impl<T: PoolClient + Sized + Sync + Send + 'static> ProofHandler for NewProofOfSpaceHandle<T> {
    async fn handle_proof(&self, new_pos: NewProofOfSpace) -> Result<(), Error> {
        if let Some(sps) = self
            .shared_state
            .signage_points
            .lock()
            .await
            .get(&new_pos.sp_hash)
        {
            for sp in sps {
                if let Some(qs) = verify_and_get_quality_string(
                    &new_pos.proof,
                    self.constants,
                    &new_pos.challenge_hash,
                    &new_pos.sp_hash,
                ) {
                    let required_iters = calculate_iterations_quality(
                        self.constants.difficulty_constant_factor,
                        &qs,
                        new_pos.proof.size,
                        sp.difficulty,
                        &new_pos.sp_hash,
                    );
                    if required_iters
                        < calculate_sp_interval_iters(self.constants, sp.sub_slot_iters)?
                    {
                        self._handle_proof(sp, &qs, &new_pos).await;
                    }
                    if let Some(p2_singleton_puzzle_hash) = &new_pos.proof.pool_contract_puzzle_hash
                    {
                        self.handle_partial(p2_singleton_puzzle_hash, &qs, new_pos.clone())
                            .await?;
                    } else {
                        warn!("Not a pooling proof of space");
                    }
                } else {
                    warn!("Invalid proof of space {:?}", new_pos);
                }
            }
        } else {
            warn!(
                "Received response for a signage point that we do not have {}",
                &new_pos.sp_hash
            );
        }
        Ok(())
    }
}

impl<T: PoolClient + Sized + Sync + Send + 'static> NewProofOfSpaceHandle<T> {
    async fn _handle_proof(&self, sp: &NewSignagePoint, qs: &Bytes32, new_pos: &NewProofOfSpace) {
        let mut farmer_pos = self.shared_state.proofs_of_space.lock().await;
        if farmer_pos.get(&new_pos.sp_hash).is_none() {
            farmer_pos.insert(new_pos.sp_hash, vec![]);
        }
        farmer_pos
            .get_mut(&new_pos.sp_hash)
            .expect("Should not happen, item created above")
            .push((new_pos.plot_identifier.clone(), new_pos.proof.clone()));
        self.shared_state
            .cache_time
            .lock()
            .await
            .insert(new_pos.sp_hash, Instant::now());
        self.shared_state
            .quality_to_identifiers
            .lock()
            .await
            .insert(
                *qs,
                FarmerIdentifier {
                    plot_identifier: new_pos.plot_identifier.clone(),
                    challenge_hash: new_pos.challenge_hash,
                    sp_hash: new_pos.sp_hash,
                    harvester_id: self.harvester_id,
                },
            );
        self.shared_state
            .cache_time
            .lock()
            .await
            .insert(*qs, Instant::now());
        let sig_handle = RespondSignaturesHandler {
            pool_client: self.pool_client.clone(),
            shared_state: self.shared_state.clone(),
            harvester_id: self.harvester_id,
            harvesters: self.harvesters.clone(),
            constants: self.constants,
        };
        let request = RequestSignatures {
            plot_identifier: new_pos.plot_identifier.clone(),
            challenge_hash: new_pos.challenge_hash,
            sp_hash: new_pos.sp_hash,
            messages: vec![sp.challenge_chain_sp, sp.reward_chain_sp],
        };
        if let Some(h) = self.harvesters.get(&self.harvester_id) {
            let harvester = h.clone();
            tokio::spawn(async move {
                match harvester.as_ref() {
                    Harvesters::DruidGarden(harvester) => {
                        let _ = harvester.request_signatures(request, sig_handle).await;
                    }
                }
            });
        }
    }

    async fn handle_partial(
        &self,
        p2_singleton_puzzle_hash: &Bytes32,
        qs: &Bytes32,
        new_pos: NewProofOfSpace,
    ) -> Result<(), Error> {
        if let Some(pool_state) = self
            .shared_state
            .pool_states
            .lock()
            .await
            .get_mut(p2_singleton_puzzle_hash)
        {
            if let Some(pool_config) = &pool_state.pool_config {
                if pool_config.pool_url.is_empty() {
                } else if let Some(pool_dif) = pool_state.current_difficulty {
                    let required_iters = calculate_iterations_quality(
                        self.constants.difficulty_constant_factor,
                        qs,
                        new_pos.proof.size,
                        pool_dif,
                        &new_pos.sp_hash,
                    );
                    let pool_required_iters = calculate_sp_interval_iters(
                        self.constants,
                        self.constants.pool_sub_slot_iters,
                    )?;
                    if required_iters >= pool_required_iters {
                        info!(
                            "Proof of space not good enough for pool {}: {:?}",
                            pool_config.pool_url, pool_state.current_difficulty
                        );
                    } else if let Some(auth_token_timeout) = pool_state.authentication_token_timeout
                    {
                        let payload = PostPartialPayload {
                            launcher_id: pool_config.launcher_id,
                            authentication_token: get_current_authentication_token(
                                auth_token_timeout,
                            ),
                            proof_of_space: new_pos.proof.clone(),
                            sp_hash: new_pos.sp_hash,
                            end_of_sub_slot: new_pos.signage_point_index == 0,
                            harvester_id: Bytes32::new(&hash_256(self.harvester_id)),
                        };
                        let payload_bytes = hash_256(payload.to_bytes());
                        let request = RequestSignatures {
                            plot_identifier: new_pos.plot_identifier.clone(),
                            challenge_hash: new_pos.challenge_hash,
                            sp_hash: new_pos.sp_hash,
                            messages: vec![Bytes32::new(&payload_bytes)],
                        };
                        let handler = PartialHandler {
                            pool_client: self.pool_client.clone(),
                            shared_state: self.shared_state.clone(),
                            p2_singleton_puzzle_hash: *p2_singleton_puzzle_hash,
                            new_pos,
                            auth_token_timeout,
                            payload,
                            payload_bytes,
                        };
                        if let Some(h) = self.harvesters.get(&self.harvester_id) {
                            let harvester = h.clone();
                            tokio::spawn(async move {
                                match harvester.as_ref() {
                                    Harvesters::DruidGarden(h) => {
                                        let _ = h.request_signatures(request, handler).await;
                                    }
                                }
                            });
                        }
                    } else {
                        warn!("No pool specific authentication_token_timeout has been set for {p2_singleton_puzzle_hash}, check communication with the pool.");
                    }
                } else {
                    warn!("No pool specific difficulty has been set for {p2_singleton_puzzle_hash}, check communication with the pool, skipping this partial to {}.", pool_config.pool_url);
                }
            } else {
                warn!("No Pool Config for {p2_singleton_puzzle_hash}");
            }
        } else {
            warn!("Did not find pool info for {p2_singleton_puzzle_hash}");
        }
        Ok(())
    }
}

pub struct PartialHandler<T: PoolClient + Sized + Sync + Send + 'static> {
    pub pool_client: Arc<T>,
    pub shared_state: Arc<FarmerSharedState>,
    pub auth_token_timeout: u8,
    pub p2_singleton_puzzle_hash: Bytes32,
    pub new_pos: NewProofOfSpace,
    pub payload: PostPartialPayload,
    pub payload_bytes: Vec<u8>,
}
#[async_trait]
impl<T: PoolClient + Sized + Sync + Send + 'static> SignatureHandler for PartialHandler<T> {
    async fn handle_signature(&self, respond_sigs: RespondSignatures) -> Result<(), Error> {
        let response_msg_sig = if let Some(f) = respond_sigs.message_signatures.first() {
            Signature::from_bytes(f.1.to_sized_bytes())
                .map_err(|e| Error::new(ErrorKind::InvalidInput, format!("{:?}", e)))?
        } else {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "No Signature in Response",
            ));
        };
        let mut plot_sig = None;
        let local_pk = PublicKey::from_bytes(respond_sigs.local_pk.to_sized_bytes())
            .map_err(|e| Error::new(ErrorKind::InvalidInput, format!("{:?}", e)))?;
        for (_, sk) in self.shared_state.farmer_private_keys.iter() {
            let pk = sk.sk_to_pk();
            if pk.to_bytes() == *respond_sigs.farmer_pk.to_sized_bytes() {
                let agg_pk = generate_plot_public_key(&local_pk, &pk, true)?;
                if agg_pk.to_bytes() != *self.new_pos.proof.plot_public_key.to_sized_bytes() {
                    return Err(Error::new(ErrorKind::InvalidInput, "Key Mismatch"));
                }
                let sig_farmer = sign_prepend(sk, &self.payload_bytes, &agg_pk);
                let taproot_sk = generate_taproot_sk(&local_pk, &pk)?;
                let taproot_sig = sign_prepend(&taproot_sk, &self.payload_bytes, &agg_pk);
                let p_sig = AggregateSignature::aggregate(
                    &[&sig_farmer, &response_msg_sig, &taproot_sig],
                    true,
                )
                .map_err(|e| Error::new(ErrorKind::InvalidInput, format!("{:?}", e)))?;
                if p_sig.to_signature().verify(
                    true,
                    &self.payload_bytes,
                    AUG_SCHEME_DST,
                    &agg_pk.to_bytes(),
                    &agg_pk,
                    true,
                ) != BLST_ERROR::BLST_SUCCESS
                {
                    warn!(
                        "Failed to validate partial signature {:?}",
                        p_sig.to_signature()
                    );
                    continue;
                }
                plot_sig = Some(p_sig);
            }
        }
        if let Some(pool_state) = self
            .shared_state
            .pool_states
            .lock()
            .await
            .get_mut(&self.p2_singleton_puzzle_hash)
        {
            if let Some(pool_config) = &pool_state.pool_config {
                if let Some(auth_key) = self
                    .shared_state
                    .auth_secret_keys
                    .get(&pool_config.owner_public_key)
                {
                    let auth_sig = sign(auth_key, &self.payload_bytes);
                    if let Some(plot_sig) = plot_sig {
                        let agg_sig = AggregateSignature::aggregate(
                            &[&plot_sig.to_signature(), &auth_sig],
                            true,
                        )
                        .map_err(|e| Error::new(ErrorKind::InvalidInput, format!("{:?}", e)))?;
                        let post_request = PostPartialRequest {
                            payload: self.payload.clone(),
                            aggregate_signature: agg_sig.to_signature().to_bytes().into(),
                        };
                        info!(
                            "Submitting partial for {} to {}",
                            post_request.payload.launcher_id.to_string(),
                            &pool_config.pool_url
                        );
                        match self
                            .pool_client
                            .post_partial(
                                &pool_config.pool_url,
                                post_request,
                                &Some(HEADERS.clone()),
                            )
                            .await
                        {
                            Ok(resp) => {
                                pool_state.current_points += resp.new_difficulty;
                                if pool_state.current_difficulty != Some(resp.new_difficulty) {
                                    info!(
                                        "New Pool Difficulty: {:?} ",
                                        pool_state.current_difficulty
                                    );
                                }
                                pool_state.current_difficulty = Some(resp.new_difficulty);
                                info!("Current Points: {:?} ", pool_state.current_points);
                            }
                            Err(e) => {
                                error!("Error in pooling: {:?}", e);
                                if e.error_code == PoolErrorCode::ProofNotGoodEnough as u8 {
                                    error!("Partial not good enough, forcing pool farmer update to get our current difficulty.");
                                    self.shared_state
                                        .force_pool_update
                                        .store(true, Ordering::Relaxed);
                                }
                                if e.error_code == PoolErrorCode::InvalidSignature as u8 {
                                    error!("Invalid Signature, Forcing Pool Update");
                                    pool_state.next_farmer_update = Instant::now();
                                }
                            }
                        }
                    }
                } else {
                    warn!(
                        "No authentication sk for {}",
                        &self.p2_singleton_puzzle_hash
                    );
                }
            } else {
                warn!("No Pool Config for {}", &self.p2_singleton_puzzle_hash);
            }
        } else {
            warn!(
                "Did not find pool info for {}",
                &self.p2_singleton_puzzle_hash
            );
        }
        Ok(())
    }
}
