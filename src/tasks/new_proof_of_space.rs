use std::io::{Error, ErrorKind};
use std::sync::Arc;
use std::time::Instant;
use blst::BLST_ERROR;
use blst::min_pk::{AggregateSignature, PublicKey, Signature};
use log::{debug, error, info, warn};
use dg_xch_clients::protocols::harvester::{NewProofOfSpace, RequestSignatures, RespondSignatures};
use dg_xch_clients::protocols::pool::{get_current_authentication_token, PoolErrorCode, PostPartialPayload, PostPartialRequest};
use dg_xch_clients::protocols::ProtocolMessageTypes;
use dg_xch_clients::websocket::{ChiaMessage, oneshot};
use dg_xch_core::blockchain::proof_of_space::{generate_plot_public_key, generate_taproot_sk};
use dg_xch_core::blockchain::sized_bytes::{Bytes32, SizedBytes};
use dg_xch_core::clvm::bls_bindings::{AUG_SCHEME_DST, sign, sign_prepend};
use dg_xch_core::consensus::constants::CONSENSUS_CONSTANTS_MAP;
use dg_xch_core::consensus::pot_iterations::{calculate_iterations_quality, calculate_sp_interval_iters};
use dg_xch_pos::verify_and_get_quality_string;
use dg_xch_serialize::{ChiaSerialize, hash_256};
use crate::models::config::Config;
use crate::models::FarmerIdentifier;
use crate::tasks::pool_update::update_pool_farmer_info;

pub async fn new_proof_of_space(
    new_pos: NewProofOfSpace,
    config: Arc<Config>
) -> Result<(), Error> {
    let constants = CONSENSUS_CONSTANTS_MAP
        .get(&config.selected_network)
        .cloned()
        .unwrap_or_default();
    if let Some(qs) = verify_and_get_quality_string(
        &new_pos.proof,
        &constants,
        &new_pos.signage_point.challenge_hash,
        &new_pos.signage_point.challenge_chain_sp,
    ) {
        let required_iters = calculate_iterations_quality(
            constants.difficulty_constant_factor,
            &qs,
            new_pos.proof.size,
            new_pos.signage_point.difficulty,
            &new_pos.signage_point.challenge_chain_sp,
        );
        if required_iters
            < calculate_sp_interval_iters(&constants, new_pos.signage_point.sub_slot_iters)?
        {
            let request = RequestSignatures {
                plot_identifier: new_pos.plot_identifier.clone(),
                challenge_hash: new_pos.signage_point.challenge_hash.clone(),
                sp_hash: new_pos.signage_point.challenge_chain_sp.clone(),
                messages: vec![
                    new_pos.signage_point.challenge_chain_sp.clone(),
                    new_pos.signage_point.reward_chain_sp.clone(),
                ],
            };
            let mut farmer_pos = proofs_of_space.lock().await;
            if farmer_pos.get(&new_pos.sp_hash).is_none() {
                farmer_pos.insert(new_pos.sp_hash.clone(), vec![]);
            }
            farmer_pos
                .get_mut(&new_pos.sp_hash)
                .expect("Should not happen, item created above")
                .push((new_pos.plot_identifier.clone(), new_pos.proof.clone()));
            cache_time
                .lock()
                .await
                .insert(message.sp_hash.clone(), Instant::now());
            quality_to_identifiers.lock().await.insert(
                qs.clone(),
                FarmerIdentifier {
                    plot_identifier: message.plot_identifier.clone(),
                    challenge_hash: message.challenge_hash.clone(),
                    sp_hash: message.sp_hash.clone(),
                },
            );
            cache_time
                .lock()
                .await
                .insert(qs.clone(), Instant::now());
            let _ = request_signature_sender.send(request).await;
        }
        if let Some(p2_singleton_puzzle_hash) =
            &new_pos.proof.pool_contract_puzzle_hash
        {
            if let Some(pool_state) = pool_state
                .lock()
                .await
                .get_mut(p2_singleton_puzzle_hash)
            {
                if let Some(pool_config) = pool_state.pool_config.clone() {
                    let (pool_url, launcher_id) = (
                        pool_config.pool_url.as_str(),
                        pool_config.launcher_id.clone(),
                    );
                    if pool_url.is_empty() {
                        return Ok(());
                    }
                    if let Some(pool_dif) = pool_state.current_difficulty {
                        let required_iters = calculate_iterations_quality(
                            constants.difficulty_constant_factor,
                            &qs,
                            message.proof.size,
                            pool_dif,
                            &message.sp_hash,
                        );
                        if required_iters
                            >= calculate_sp_interval_iters(
                            &constants,
                            constants.pool_sub_slot_iters,
                        )?
                        {
                            info!(
                                "Proof of space not good enough for pool {}: {:?}",
                                pool_url, pool_state.current_difficulty
                            );
                            return Ok(());
                        }
                        if let Some(auth_token_timeout) =
                            pool_state.authentication_token_timeout
                        {
                            let is_eos = message.signage_point_index == 0;
                            let payload = PostPartialPayload {
                                launcher_id: launcher_id.clone(),
                                authentication_token:
                                get_current_authentication_token(
                                    auth_token_timeout,
                                ),
                                proof_of_space: message.proof.clone(),
                                sp_hash: message.sp_hash.clone(),
                                end_of_sub_slot: is_eos,
                                harvester_id: self.peer_id.as_ref().clone(),
                            };
                            let to_sign = hash_256(payload.to_bytes());
                            let request = RequestSignatures {
                                plot_identifier: message.plot_identifier.clone(),
                                challenge_hash: message.challenge_hash.clone(),
                                sp_hash: message.sp_hash.clone(),
                                messages: vec![Bytes32::new(&to_sign)],
                            };
                            let respond_sigs: RespondSignatures = oneshot(
                                peer.websocket.clone(),
                                ChiaMessage::new(
                                    ProtocolMessageTypes::RequestSignatures,
                                    &request,
                                ),
                                Some(ProtocolMessageTypes::RespondSignatures),
                            )
                                .await?;
                            let response_msg_sig = if let Some(f) =
                                respond_sigs.message_signatures.first()
                            {
                                Signature::from_bytes(&f.1.to_sized_bytes())
                                    .map_err(|e| {
                                        Error::new(
                                            ErrorKind::InvalidInput,
                                            format!("{:?}", e),
                                        )
                                    })?
                            } else {
                                return Err(Error::new(
                                    ErrorKind::InvalidInput,
                                    "No Signature in Response",
                                ));
                            };
                            let mut plot_sig = None;
                            let local_pk = PublicKey::from_bytes(
                                &respond_sigs.local_pk.to_sized_bytes(),
                            )
                                .map_err(|e| {
                                    Error::new(
                                        ErrorKind::InvalidInput,
                                        format!("{:?}", e),
                                    )
                                })?;
                            for sk in farmer_private_keys
                                .lock()
                                .await
                                .iter()
                            {
                                let pk = sk.sk_to_pk();
                                if pk.to_bytes()
                                    == respond_sigs.farmer_pk.to_sized_bytes()
                                {
                                    let agg_pk = generate_plot_public_key(
                                        &local_pk, &pk, true,
                                    )?;
                                    if agg_pk.to_bytes()
                                        != new_pos
                                        .proof
                                        .plot_public_key
                                        .to_sized_bytes()
                                    {
                                        return Err(Error::new(
                                            ErrorKind::InvalidInput,
                                            "Key Mismatch",
                                        ));
                                    }
                                    let sig_farmer =
                                        sign_prepend(sk, &to_sign, &agg_pk);
                                    let taproot_sk =
                                        generate_taproot_sk(&local_pk, &pk)?;
                                    let taproot_sig = sign_prepend(
                                        &taproot_sk,
                                        &to_sign,
                                        &agg_pk,
                                    );

                                    let p_sig = AggregateSignature::aggregate(
                                        &[
                                            &sig_farmer,
                                            &response_msg_sig,
                                            &taproot_sig,
                                        ],
                                        true,
                                    )
                                        .map_err(|e| {
                                            Error::new(
                                                ErrorKind::InvalidInput,
                                                format!("{:?}", e),
                                            )
                                        })?;
                                    if p_sig.to_signature().verify(
                                        true,
                                        to_sign.as_ref(),
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
                            if let Some(auth_key) = auth_secret_keys
                                .lock()
                                .await
                                .get(&pool_config.owner_public_key)
                            {
                                let auth_sig = sign(auth_key, &to_sign);
                                if let Some(plot_sig) = plot_sig {
                                    let agg_sig =
                                        AggregateSignature::aggregate(
                                            &[
                                                &plot_sig.to_signature(),
                                                &auth_sig,
                                            ],
                                            true,
                                        )
                                            .map_err(|e| {
                                                Error::new(
                                                    ErrorKind::InvalidInput,
                                                    format!("{:?}", e),
                                                )
                                            })?;
                                    let post_request = PostPartialRequest {
                                        payload,
                                        aggregate_signature: agg_sig
                                            .to_signature()
                                            .to_bytes()
                                            .into(),
                                    };
                                    debug!(
                                            "Submitting partial for {} to {}",
                                            post_request
                                                .payload
                                                .launcher_id
                                                .to_string(),
                                            pool_url
                                        );
                                    pool_state.points_found_since_start +=
                                        pool_state
                                            .current_difficulty
                                            .unwrap_or_default();
                                    pool_state.points_found_24h.push((
                                        Instant::now(),
                                        pool_state
                                            .current_difficulty
                                            .unwrap_or_default(),
                                    ));
                                    debug!(
                                            "POST /partial request {:?}",
                                            &post_request
                                        );
                                    match pool_client
                                        .post_partial(pool_url, post_request)
                                        .await
                                    {
                                        Ok(resp) => {
                                            pool_state
                                                .points_acknowledged_since_start +=
                                                resp.new_difficulty;
                                            pool_state.current_points +=
                                                resp.new_difficulty;
                                            pool_state
                                                .points_acknowledged_24h
                                                .push((
                                                    Instant::now(),
                                                    pool_state
                                                        .current_difficulty
                                                        .unwrap_or_default(),
                                                ));
                                            pool_state.current_difficulty =
                                                Some(resp.new_difficulty);
                                            info!(
                                                    "New Pool Difficulty: {:?} ",
                                                    pool_state.current_difficulty
                                                );
                                            info!(
                                                    "Current Points: {:?} ",
                                                    pool_state.current_points
                                                );
                                        }
                                        Err(e) => {
                                            error!("Error in pooling: {:?}", e);
                                            pool_state.pool_errors_24h.push((
                                                Instant::now(),
                                                format!("{:?}", e),
                                            ));
                                            if e.error_code
                                                == PoolErrorCode::ProofNotGoodEnough as u8
                                            {
                                                error!("Partial not good enough, forcing pool farmer update to get our current difficulty.");
                                                pool_state.next_farmer_update = Instant::now();
                                                let _ = update_pool_farmer_info(
                                                    pool_state,
                                                    &pool_config,
                                                    auth_token_timeout,
                                                    auth_key,
                                                    pool_client.clone()
                                                )
                                                    .await;
                                            }
                                            return Ok(());
                                        }
                                    }
                                }
                            } else {
                                warn!("No authentication sk for {p2_singleton_puzzle_hash}");
                                return Ok(());
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
                    warn!("No Pool Config for {p2_singleton_puzzle_hash}, Unable to submit partial");
                    return Ok(());
                }
            } else {
                warn!("Did not find pool info for {p2_singleton_puzzle_hash}, Unable to submit partial");
                return Ok(());
            }
        } else {
            debug!("OG proof of space, no partial to submit");
        }
    } else {
        warn!("Invalid proof of space {:?}", new_pos);
    }
    Ok(())
}