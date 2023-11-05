use crate::farmer::protocols::harvester::respond_signatures::RespondSignaturesHandler;
use crate::farmer::{FarmerIdentifier, FarmerSharedState};
use crate::harvesters::{Harvester, Harvesters, ProofHandler};
use async_trait::async_trait;
use dg_xch_clients::api::pool::PoolClient;
use dg_xch_clients::protocols::harvester::{NewProofOfSpace, RequestSignatures};
use dg_xch_clients::protocols::pool::{get_current_authentication_token, PostPartialPayload};
use dg_xch_core::blockchain::proof_of_space::ProofBytes;
use dg_xch_core::blockchain::sized_bytes::{Bytes32, SizedBytes};
use dg_xch_core::consensus::constants::CONSENSUS_CONSTANTS_MAP;
use dg_xch_core::consensus::pot_iterations::{
    calculate_iterations_quality, calculate_sp_interval_iters,
};
use dg_xch_pos::verifier::proof_to_bytes;
use dg_xch_pos::verify_and_get_quality_string;
use dg_xch_serialize::{hash_256, ChiaSerialize};
use log::{debug, warn};
use std::collections::HashMap;
use std::io::Error;
use std::sync::Arc;
use std::time::Instant;
use uuid::Uuid;

pub struct NewProofOfSpaceHandle<T: PoolClient + Sized + Sync + Send + 'static> {
    pub pool_client: Arc<T>,
    pub shared_state: Arc<FarmerSharedState>,
    pub harvester_id: Uuid,
    pub harvesters: Arc<HashMap<Uuid, Harvesters>>,
    pub sig_responder: Arc<RespondSignaturesHandler<T>>,
}

#[async_trait]
impl<T: PoolClient + Sized + Sync + Send + 'static> ProofHandler for NewProofOfSpaceHandle<T> {
    async fn handle_proof(&self, mut new_pos: NewProofOfSpace) -> Result<(), Error> {
        if let Some(sps) = self
            .shared_state
            .signage_points
            .lock()
            .await
            .get(&new_pos.sp_hash)
        {
            let constants = CONSENSUS_CONSTANTS_MAP
                .get(&self.shared_state.config.selected_network)
                .cloned()
                .unwrap_or_default();
            for sp in sps {
                if let Some((qs, reordered_proof)) = verify_and_get_quality_string(
                    &new_pos.proof,
                    &constants,
                    &new_pos.challenge_hash,
                    &new_pos.sp_hash,
                ) {
                    let required_iters = calculate_iterations_quality(
                        constants.difficulty_constant_factor,
                        &qs,
                        new_pos.proof.size,
                        sp.difficulty,
                        &new_pos.sp_hash,
                    );
                    if required_iters < calculate_sp_interval_iters(&constants, sp.sub_slot_iters)?
                    {
                        let request = RequestSignatures {
                            plot_identifier: new_pos.plot_identifier.clone(),
                            challenge_hash: new_pos.challenge_hash,
                            sp_hash: new_pos.sp_hash,
                            messages: vec![sp.challenge_chain_sp, sp.reward_chain_sp],
                        };
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
                                qs,
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
                            .insert(qs, Instant::now());
                        if let Some(h) = self.harvesters.get(&self.harvester_id) {
                            match h {
                                Harvesters::DruidGarden(h) => {
                                    let _ = h
                                        .request_signatures(request, self.sig_responder.clone())
                                        .await;
                                }
                            }
                        }
                    }
                    if let Some(p2_singleton_puzzle_hash) = &new_pos.proof.pool_contract_puzzle_hash
                    {
                        new_pos.proof.proof = ProofBytes::from(proof_to_bytes(&reordered_proof));
                        if let Some(pool_state) = self
                            .shared_state
                            .pool_states
                            .lock()
                            .await
                            .get_mut(p2_singleton_puzzle_hash)
                        {
                            if let Some(pool_config) = pool_state.pool_config.clone() {
                                let (pool_url, launcher_id) =
                                    (pool_config.pool_url.as_str(), pool_config.launcher_id);
                                if pool_url.is_empty() {
                                    return Ok(());
                                }
                                if let Some(pool_dif) = pool_state.current_difficulty {
                                    let required_iters = calculate_iterations_quality(
                                        constants.difficulty_constant_factor,
                                        &qs,
                                        new_pos.proof.size,
                                        pool_dif,
                                        &new_pos.sp_hash,
                                    );
                                    if required_iters
                                        >= calculate_sp_interval_iters(
                                            &constants,
                                            constants.pool_sub_slot_iters,
                                        )?
                                    {
                                        debug!(
                                            "Proof of space not good enough for pool {}: {:?}",
                                            pool_url, pool_state.current_difficulty
                                        );
                                        return Ok(());
                                    }
                                    if let Some(auth_token_timeout) =
                                        pool_state.authentication_token_timeout
                                    {
                                        let is_eos = new_pos.signage_point_index == 0;
                                        let payload = PostPartialPayload {
                                            launcher_id,
                                            authentication_token: get_current_authentication_token(
                                                auth_token_timeout,
                                            ),
                                            proof_of_space: new_pos.proof.clone(),
                                            sp_hash: new_pos.sp_hash,
                                            end_of_sub_slot: is_eos,
                                            harvester_id: Bytes32::new(&hash_256(
                                                self.harvester_id,
                                            )),
                                        };
                                        let to_sign = hash_256(payload.to_bytes());
                                        let request = RequestSignatures {
                                            plot_identifier: new_pos.plot_identifier.clone(),
                                            challenge_hash: new_pos.challenge_hash,
                                            sp_hash: new_pos.sp_hash,
                                            messages: vec![Bytes32::new(&to_sign)],
                                        };
                                        if let Some(h) = self.harvesters.get(&self.harvester_id) {
                                            match h {
                                                Harvesters::DruidGarden(h) => {
                                                    let _ = h
                                                        .request_signatures(
                                                            request,
                                                            self.sig_responder.clone(),
                                                        )
                                                        .await;
                                                }
                                            }
                                        }
                                    } else {
                                        warn!("No pool specific authentication_token_timeout has been set for {p2_singleton_puzzle_hash}, check communication with the pool.");
                                        return Ok(());
                                    }
                                } else {
                                    warn!("No pool specific difficulty has been set for {p2_singleton_puzzle_hash}, check communication with the pool, skipping this partial to {}.", pool_url);
                                    return Ok(());
                                }
                            } else {
                                warn!("No Pool Config for {p2_singleton_puzzle_hash}");
                                return Ok(());
                            }
                        } else {
                            warn!("Did not find pool info for {p2_singleton_puzzle_hash}");
                            return Ok(());
                        }
                    } else {
                        debug!("Not a pooling proof of space");
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
