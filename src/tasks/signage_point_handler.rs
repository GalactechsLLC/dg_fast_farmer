use std::collections::HashMap;
use std::io::{Error};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use hex::encode;
use log::{debug, error, info, trace, warn};
use tokio::sync::Mutex;
use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;
use dg_xch_clients::protocols::farmer::NewSignagePoint;
use dg_xch_clients::protocols::harvester::{NewProofOfSpace, PoolDifficulty};
use dg_xch_core::blockchain::proof_of_space::{calculate_pos_challenge, passes_plot_filter, ProofBytes, ProofOfSpace};
use dg_xch_core::blockchain::sized_bytes::{Bytes32, SizedBytes};
use dg_xch_core::consensus::constants::CONSENSUS_CONSTANTS_MAP;
use dg_xch_core::consensus::pot_iterations::{calculate_iterations_quality, calculate_sp_interval_iters, POOL_SUB_SLOT_ITERS};
use dg_xch_core::plots::PlotHeader;
use crate::models::config::Config;
use crate::models::PlotInfo;
use crate::tasks::new_proof_of_space::new_proof_of_space;

pub async fn signage_point_handler(
    signage_point: (NewSignagePoint, Vec<PoolDifficulty>),
    config: Arc<Config>,
    plots: Arc<Mutex<HashMap<String, Arc<PlotInfo>>>>
) -> Result<(), Error> {
    trace!("{:?}", &signage_point);
    let og_total = Arc::new(AtomicUsize::new(0));
    let pool_total = Arc::new(AtomicUsize::new(0));
    let pool_passed = Arc::new(AtomicUsize::new(0));
    let og_passed = Arc::new(AtomicUsize::new(0));
    let signage_point = Arc::new(signage_point);
    let constants = Arc::new(
        CONSENSUS_CONSTANTS_MAP
            .get(&config.selected_network)
            .cloned()
            .unwrap_or_default(),
    );
    let mut jobs = FuturesUnordered::new();
    plots.lock().await.iter().for_each(|(path, info)| {
        let data_arc = signage_point.clone();
        let constants_arc = constants.clone();
        let plot_info = info.clone();
        let path = path.clone();
        let og_total = og_total.clone();
        let pool_total = pool_total.clone();
        let og_passed = og_passed.clone();
        let pool_passed = pool_passed.clone();
        let mut responses = vec![];
        jobs.push(tokio::task::spawn_blocking(move || {
            if plot_info.pool_public_key.is_some() {
                og_total.fetch_add(1, Ordering::Relaxed);
            } else {
                pool_total.fetch_add(1, Ordering::Relaxed);
            }
            let plot_id = match plot_info.prover.header.as_ref() {
                PlotHeader::V1(h) => h.id,
                PlotHeader::V2(h) => h.id
            };
            let k = match plot_info.prover.header.as_ref() {
                PlotHeader::V1(h) => h.k,
                PlotHeader::V2(h) => h.k
            };
            let memo = match plot_info.prover.header.as_ref() {
                PlotHeader::V1(h) => h.memo,
                PlotHeader::V2(h) => h.memo
            };
            if passes_plot_filter(
                constants_arc.as_ref(),
                &plot_id,
                &data_arc.0.challenge_hash,
                &data_arc.0.challenge_chain_sp,
            ) {
                if plot_info.pool_public_key.is_some() {
                    og_passed.fetch_add(1, Ordering::Relaxed);
                } else {
                    pool_passed.fetch_add(1, Ordering::Relaxed);
                }
                let sp_challenge_hash = calculate_pos_challenge(
                    &plot_id,
                    &data_arc.0.challenge_hash,
                    &data_arc.0.challenge_chain_sp,
                );

                let qualities = plot_info
                    .prover
                    .get_qualities_for_challenge(&sp_challenge_hash)
                    .unwrap_or_default();
                if !qualities.is_empty() {
                    trace!("Qualities Found: {}", qualities.len());
                    let mut dif = data_arc.0.difficulty;
                    let mut sub_slot_iters = data_arc.0.sub_slot_iters;
                    let mut is_partial = false;
                    if let Some(pool_contract_puzzle_hash) =
                        &memo.pool_contract_puzzle_hash
                    {
                        for p_dif in &data_arc.1 {
                            if p_dif.pool_contract_puzzle_hash
                                == *pool_contract_puzzle_hash
                            {
                                debug!("Setting Difficulty for pool: {}", dif);
                                dif = p_dif.difficulty;
                                sub_slot_iters = p_dif.sub_slot_iters;
                                is_partial = true;
                            } else {
                                warn!("Pool Contract mismatch: {} != {}", p_dif.pool_contract_puzzle_hash, pool_contract_puzzle_hash);
                            }
                        }
                    }
                    for (index, quality) in qualities.into_iter().enumerate() {
                        let required_iters = calculate_iterations_quality(
                            constants_arc.difficulty_constant_factor,
                            &Bytes32::new(&quality.to_bytes()),
                            k,
                            dif,
                            &data_arc.0.challenge_chain_sp,
                        );
                        if let Ok(sp_interval_iters) =
                            calculate_sp_interval_iters(&constants_arc, sub_slot_iters)
                        {
                            if required_iters < sp_interval_iters {
                                match plot_info.prover.get_full_proof(
                                    &sp_challenge_hash,
                                    index,
                                    true,
                                ) {
                                    Ok(proof_xs) => {
                                        debug!("File: {:?} Plot ID: {}, challenge: {sp_challenge_hash}, plot_info: {:?}, Quality Str: {}, proof_xs: {}", path, &plot_id, plot_info.as_ref(), encode(quality.to_bytes()), encode(&proof_xs)
                                            );
                                        responses.push((
                                            quality,
                                            ProofOfSpace {
                                                challenge: sp_challenge_hash.clone(),
                                                pool_contract_puzzle_hash: plot_info
                                                    .pool_contract_puzzle_hash
                                                    .clone(),
                                                plot_public_key: plot_info
                                                    .plot_public_key
                                                    .clone(),
                                                pool_public_key: plot_info
                                                    .pool_public_key
                                                    .clone(),
                                                proof: ProofBytes::from(proof_xs),
                                                size: k,
                                            },
                                            is_partial
                                        ));
                                    }
                                    Err(e) => {
                                        error!("Failed to read Proof: {:?}", e);
                                    }
                                }
                            } else {
                                trace!(
                                    "Not Enough Iterations: {} > {}",
                                    required_iters, sp_interval_iters
                                );
                            }
                        }
                    }
                }
            }
            (path.clone(), responses)
        }));
    });
    let proofs = AtomicU64::new(0);
    let partials = AtomicU64::new(0);
    while let Some(Ok((path, responses))) = jobs.next().await {
        for (quality, proof, is_partial) in responses {
            let mut pool_difficulties = vec![];
            for (p2_singleton_puzzle_hash, pool_dict) in pool_state.lock().await.iter() {
                if let Some(config) = &pool_dict.pool_config {
                    if config.pool_url.is_empty() {
                        //Self Pooling
                        continue;
                    }
                    if let Some(difficulty) = pool_dict.current_difficulty {
                        debug!("Setting Difficulty for pool: {}", difficulty);
                        pool_difficulties.push(PoolDifficulty {
                            difficulty,
                            sub_slot_iters: POOL_SUB_SLOT_ITERS,
                            pool_contract_puzzle_hash: *p2_singleton_puzzle_hash,
                        })
                    } else {
                        warn!("No pool specific difficulty has been set for {p2_singleton_puzzle_hash}, check communication with the pool, skipping this signage point, pool: {}", &config.pool_url);
                        continue;
                    }
                }
            }
            new_proof_of_space(NewProofOfSpace {
                challenge_hash: signage_point.0.challenge_hash,
                plot_identifier: encode(quality.to_bytes()) + path.as_str(),
                proof,
                sp_hash: Default::default(),
                signage_point_index: 0,
            });
            if is_partial {
                partials.fetch_add(1, Ordering::Relaxed);
            } else {
                proofs.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}
    info!(
        "OG Passed Filter: {}/{}. Pool Passed Filter: {}/{}. Proofs Found: {}. Partials Found: {}",
        og_passed.load(Ordering::Relaxed),
        og_total.load(Ordering::Relaxed),
        pool_passed.load(Ordering::Relaxed),
        pool_total.load(Ordering::Relaxed),
        proofs.load(Ordering::Relaxed),
        partials.load(Ordering::Relaxed),
    );
    Ok(())
}