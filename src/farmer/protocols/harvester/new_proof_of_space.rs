use crate::farmer::protocols::harvester::respond_signatures::RespondSignaturesHandler;
use crate::farmer::{load_client_id, ExtendedFarmerSharedState, FarmerSharedState};
use crate::harvesters::{Harvester, Harvesters, ProofHandler, SignatureHandler};
use crate::HEADERS;
use async_trait::async_trait;
use blst::min_pk::{AggregateSignature, PublicKey, Signature};
use blst::BLST_ERROR;
use dg_xch_clients::api::pool::PoolClient;
use dg_xch_core::blockchain::proof_of_space::{generate_plot_public_key, generate_taproot_sk};
use dg_xch_core::blockchain::sized_bytes::{Bytes32, SizedBytes};
use dg_xch_core::clvm::bls_bindings::{sign, sign_prepend, AUG_SCHEME_DST};
use dg_xch_core::consensus::constants::ConsensusConstants;
use dg_xch_core::consensus::pot_iterations::{
    calculate_iterations_quality, calculate_sp_interval_iters,
};
use dg_xch_core::protocols::farmer::{FarmerIdentifier, NewSignagePoint};
use dg_xch_core::protocols::harvester::{
    NewProofOfSpace, RequestSignatures, RespondSignatures, SignatureRequestSourceData,
    SigningDataKind,
};
use dg_xch_core::protocols::pool::{
    get_current_authentication_token, PoolErrorCode, PostPartialPayload, PostPartialRequest,
};
use dg_xch_pos::verify_and_get_quality_string;
use dg_xch_serialize::{hash_256, ChiaSerialize};
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Instant;

pub struct NewProofOfSpaceHandle<T: PoolClient + Sized + Sync + Send + 'static> {
    pub pool_client: Arc<T>,
    pub shared_state: Arc<FarmerSharedState<ExtendedFarmerSharedState>>,
    pub harvester_id: Bytes32,
    pub harvesters: Arc<HashMap<Bytes32, Arc<Harvesters>>>,
    pub constants: &'static ConsensusConstants,
}

#[async_trait]
impl<T: PoolClient + Sized + Sync + Send + 'static> ProofHandler for NewProofOfSpaceHandle<T> {
    async fn handle_proof(&self, new_pos: NewProofOfSpace) -> Result<(), Error> {
        debug!("Got NewProofOfSpace, Searching for SP: {}", new_pos.sp_hash);
        if let Some(sps) = self
            .shared_state
            .signage_points
            .lock()
            .await
            .get(&new_pos.sp_hash)
        {
            debug!("Found SignagePoint List ");
            if sps.is_empty() {
                warn!("Empty Signage Point List");
            }
            for sp in sps {
                if let Some(qs) = verify_and_get_quality_string(
                    &new_pos.proof,
                    self.constants,
                    &new_pos.challenge_hash,
                    &new_pos.sp_hash,
                    sp.peak_height,
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
                        if let Some(fee_info) = &new_pos.fee_info {
                            let mut to_hash: Vec<u8> = vec![];
                            to_hash.extend_from_slice(new_pos.proof.proof.as_ref());
                            to_hash.extend_from_slice(new_pos.proof.challenge.as_ref());
                            let condition_hash = hash_256(&to_hash);
                            let value = u32::from_be_bytes(
                                condition_hash[28..32]
                                    .try_into()
                                    .expect("Expected Cast from 4 bytes slice to [u8; 4] to Work"),
                            );
                            if value < fee_info.applied_fee_threshold {
                                info!(
                                    "Using 3rd Party Harvester Fee for challenge {}, Threshold {:.3}%/{:.3}% ({}/{})",
                                    sp.challenge_hash,
                                    value as f64 / 0xFFFFFFFFu32 as f64 * 100f64,
                                    fee_info.applied_fee_threshold as f64 / 0xFFFFFFFFu32 as f64 * 100f64,
                                    format_big_number(value),
                                    format_big_number(fee_info.applied_fee_threshold),
                                );
                            } else {
                                info!(
                                    "No Fee Used for challenge {}, {:.3}%/{:.3}% ({}/{})",
                                    sp.challenge_hash,
                                    value as f64 / 0xFFFFFFFFu32 as f64 * 100f64,
                                    fee_info.applied_fee_threshold as f64 / 0xFFFFFFFFu32 as f64
                                        * 100f64,
                                    format_big_number(value),
                                    format_big_number(fee_info.applied_fee_threshold),
                                );
                            }
                        } else {
                            info!("No Fee applied for challenge {}", sp.challenge_hash,);
                        }
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

fn format_big_number(number: u32) -> String {
    number
        .to_string()
        .as_bytes()
        .rchunks(3)
        .rev()
        .map(std::str::from_utf8)
        .collect::<Result<Vec<&str>, _>>()
        .expect("Expected u32 To be a valid String")
        .join(",")
}

impl<T: PoolClient + Sized + Sync + Send + 'static> NewProofOfSpaceHandle<T> {
    async fn _handle_proof(&self, sp: &NewSignagePoint, qs: &Bytes32, new_pos: &NewProofOfSpace) {
        {
            let mut farmer_pos = self.shared_state.proofs_of_space.lock().await;
            if farmer_pos.get(&new_pos.sp_hash).is_none() {
                farmer_pos.insert(new_pos.sp_hash, vec![]);
            }
            farmer_pos
                .get_mut(&new_pos.sp_hash)
                .expect("Should not happen, item created above")
                .push((new_pos.plot_identifier.clone(), new_pos.proof.clone()));
        }
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
                    peer_node_id: self.harvester_id,
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
        let sp_src_data = {
            if new_pos.include_source_signature_data
                || new_pos.farmer_reward_address_override.is_some()
            {
                if let Some(sp_data) = sp.sp_source_data.as_ref() {
                    let (cc, rc) = if let Some(vdf) = sp_data.vdf_data.as_ref() {
                        (
                            SignatureRequestSourceData {
                                kind: SigningDataKind::ChallengeChainVdf,
                                data: vdf.cc_vdf.to_bytes(),
                            },
                            SignatureRequestSourceData {
                                kind: SigningDataKind::RewardChainVdf,
                                data: vdf.rc_vdf.to_bytes(),
                            },
                        )
                    } else if let Some(sub_slot_data) = sp_data.sub_slot_data.as_ref() {
                        (
                            SignatureRequestSourceData {
                                kind: SigningDataKind::ChallengeChainSubSlot,
                                data: sub_slot_data.cc_sub_slot.to_bytes(),
                            },
                            SignatureRequestSourceData {
                                kind: SigningDataKind::RewardChainSubSlot,
                                data: sub_slot_data.rc_sub_slot.to_bytes(),
                            },
                        )
                    } else {
                        error!("Source Signature Did not contain any data, Cannot Sign Proof");
                        return;
                    };
                    Some(vec![Some(cc), Some(rc)])
                } else {
                    error!("Source Signature Data Request But was Null, Cannot Sign Proof");
                    return;
                }
            } else {
                None
            }
        };
        let request = RequestSignatures {
            plot_identifier: new_pos.plot_identifier.clone(),
            challenge_hash: new_pos.challenge_hash,
            sp_hash: new_pos.sp_hash,
            messages: vec![sp.challenge_chain_sp, sp.reward_chain_sp],
            message_data: sp_src_data,
            rc_block_unfinished: None,
        };
        if let Some(h) = self.harvesters.get(&self.harvester_id) {
            let harvester = h.clone();
            tokio::spawn(async move {
                match harvester.as_ref() {
                    Harvesters::DruidGarden(harvester) => {
                        if let Err(e) = harvester.request_signatures(request, sig_handle).await {
                            error!("Error Requesting Signature: {}", e);
                        }
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
                if pool_config.pool_url.is_empty()
                    || new_pos.proof.pool_contract_puzzle_hash.is_none()
                {
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
                    if required_iters > pool_required_iters {
                        warn!(
                            "Proof of space not good enough for pool {}: {:?} {qs:?}",
                            pool_config.pool_url, pool_state.current_difficulty
                        );
                    } else if let Some(auth_token_timeout) = pool_state.authentication_token_timeout
                    {
                        let shared_state = self.shared_state.clone();
                        let payload = PostPartialPayload {
                            launcher_id: pool_config.launcher_id,
                            authentication_token: get_current_authentication_token(
                                auth_token_timeout,
                            ),
                            proof_of_space: new_pos.proof.clone(),
                            sp_hash: new_pos.sp_hash,
                            end_of_sub_slot: new_pos.signage_point_index == 0,
                            harvester_id: load_client_id(shared_state.as_ref()).await?,
                        };
                        let payload_bytes = hash_256(payload.to_bytes());
                        let sp_src_data = {
                            if new_pos.include_source_signature_data
                                || new_pos.farmer_reward_address_override.is_some()
                            {
                                Some(vec![Some(SignatureRequestSourceData {
                                    kind: SigningDataKind::Partial,
                                    data: payload.to_bytes(),
                                })])
                            } else {
                                None
                            }
                        };
                        let request = RequestSignatures {
                            plot_identifier: new_pos.plot_identifier.clone(),
                            challenge_hash: new_pos.challenge_hash,
                            sp_hash: new_pos.sp_hash,
                            messages: vec![Bytes32::new(&payload_bytes)],
                            message_data: sp_src_data,
                            rc_block_unfinished: None,
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
                                        if let Err(e) = h.request_signatures(request, handler).await
                                        {
                                            error!("Error Requesting Signature: {}", e);
                                        }
                                    }
                                }
                            });
                        } else {
                            error!("Failed to find harvester with ID {}", &self.harvester_id);
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

pub struct FullProofHandler<T: PoolClient + Sized + Sync + Send + 'static> {
    pub pool_client: Arc<T>,
    pub shared_state: Arc<FarmerSharedState<ExtendedFarmerSharedState>>,
    pub auth_token_timeout: u8,
    pub p2_singleton_puzzle_hash: Bytes32,
    pub new_pos: NewProofOfSpace,
    pub payload: PostPartialPayload,
    pub payload_bytes: Vec<u8>,
}

pub struct PartialHandler<T: PoolClient + Sized + Sync + Send + 'static> {
    pub pool_client: Arc<T>,
    pub shared_state: Arc<FarmerSharedState<ExtendedFarmerSharedState>>,
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
        for (pk, sk) in self.shared_state.farmer_private_keys.iter() {
            if *pk == respond_sigs.farmer_pk {
                let agg_pk = generate_plot_public_key(&local_pk, &pk.into(), true)?;
                if agg_pk.to_bytes() != *self.new_pos.proof.plot_public_key.to_sized_bytes() {
                    return Err(Error::new(ErrorKind::InvalidInput, "Key Mismatch"));
                }
                let sig_farmer = sign_prepend(sk, &self.payload_bytes, &agg_pk);
                let taproot_sk = generate_taproot_sk(&local_pk, &pk.into())?;
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
                break;
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
                        debug!(
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
                                    pool_state.current_difficulty = Some(resp.new_difficulty);
                                }
                                info!("Current Points: {:?} ", pool_state.current_points);
                            }
                            Err(e) => {
                                error!("Error in pooling: {:?}", e);
                                if e.error_code == PoolErrorCode::ProofNotGoodEnough as u8 {
                                    error!("Partial not good enough, forcing pool farmer update to get our current difficulty.");
                                    self.shared_state
                                        .data
                                        .force_pool_update
                                        .store(true, Ordering::Relaxed);
                                }
                                if e.error_code == PoolErrorCode::InvalidSignature as u8 {
                                    error!("Invalid Signature, Forcing Pool Update");
                                    pool_state.next_farmer_update = Instant::now();
                                }
                            }
                        }
                    } else {
                        warn!("invalid plot Sig");
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
