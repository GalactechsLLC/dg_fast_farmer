use crate::PROTOCOL_VERSION;
use crate::farmer::FarmerSharedState;
use crate::farmer::config::Config;
use crate::harvesters::{Harvester, SignatureHandler};
use async_trait::async_trait;
use blst::BLST_ERROR;
use blst::min_pk::AggregateSignature;
use dg_xch_clients::api::pool::PoolClient;
use dg_xch_clients::websocket::farmer::FarmerClient;
use dg_xch_core::blockchain::pool_target::PoolTarget;
use dg_xch_core::blockchain::proof_of_space::{generate_plot_public_key, generate_taproot_sk};
use dg_xch_core::blockchain::sized_bytes::{Bytes32, Bytes96};
use dg_xch_core::clvm::bls_bindings::{sign, sign_prepend};
use dg_xch_core::consensus::constants::{CONSENSUS_CONSTANTS_MAP, ConsensusConstants, MAINNET};
use dg_xch_core::constants::AUG_SCHEME_DST;
use dg_xch_core::protocols::farmer::{DeclareProofOfSpace, SignedValues};
use dg_xch_core::protocols::harvester::RespondSignatures;
use dg_xch_core::protocols::{ChiaMessage, ProtocolMessageTypes};
use dg_xch_core::traits::SizedBytes;
use dg_xch_keys::parse_payout_address;
use dg_xch_pos::verify_and_get_quality_string;
use dg_xch_serialize::ChiaSerialize;
use log::{debug, error, info, warn};
use std::io::{Error, ErrorKind};
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_tungstenite::tungstenite::Message;

pub struct RespondSignaturesHandler<P, T, H, C>
where
    P: PoolClient + Sized + Sync + Send + 'static,
    T: Sync + Send + 'static,
    H: Harvester<T, H, C> + Sync + Send + 'static,
    C: Sync + Send + Clone + 'static,
{
    pub pool_client: Arc<P>,
    pub shared_state: Arc<FarmerSharedState<T>>,
    pub harvester: Arc<H>,
    pub constants: &'static ConsensusConstants,
    pub config: Arc<RwLock<Config<C>>>,
    pub client: Arc<RwLock<Option<FarmerClient<T>>>>,
}
#[async_trait]
impl<P, T, H, C> SignatureHandler<T, H, C> for RespondSignaturesHandler<P, T, H, C>
where
    P: PoolClient + Default + Sized + Sync + Send + 'static,
    T: Sync + Send + 'static,
    H: Harvester<T, H, C> + Sync + Send + 'static,
    C: Sync + Send + Clone + 'static,
{
    async fn load(
        shared_state: Arc<FarmerSharedState<T>>,
        config: Arc<RwLock<Config<C>>>,
        harvester: Arc<H>,
        client: Arc<RwLock<Option<FarmerClient<T>>>>,
    ) -> Result<Arc<Self>, Error> {
        let network = config.read().await.selected_network.clone();
        let s = Self {
            pool_client: Arc::new(P::default()),
            shared_state,
            harvester,
            constants: CONSENSUS_CONSTANTS_MAP.get(&network).unwrap_or(&MAINNET),
            config,
            client,
        };
        Ok(Arc::new(s))
    }

    async fn handle_signature(&self, response: RespondSignatures) -> Result<(), Error> {
        if let Some(sps) = self
            .shared_state
            .signage_points
            .read()
            .await
            .get(&response.sp_hash)
        {
            if sps.is_empty() {
                error!("Missing Signage Points for {}", &response.sp_hash);
            } else {
                let sp_index = sps
                    .first()
                    .expect("Sps was empty, Should have been caught above")
                    .signage_point_index;
                let mut is_sp_signatures = false;
                let mut found_sp_hash_debug = false;
                let peak_height = sps[0].peak_height;
                for sp_candidate in sps {
                    if Some(response.sp_hash) == response.message_signatures.first().map(|v| v.0) {
                        found_sp_hash_debug = true;
                        if Some(sp_candidate.reward_chain_sp)
                            == response.message_signatures.get(1).map(|v| v.0)
                        {
                            is_sp_signatures = true;
                        }
                    }
                }
                if found_sp_hash_debug && !is_sp_signatures {
                    return Err(Error::new(
                        ErrorKind::InvalidInput,
                        "Found SP Hash Debug, but missing reward_chain_sp signature",
                    ));
                }
                let mut pospace = None;
                if let Some(proofs) = self
                    .shared_state
                    .proofs_of_space
                    .read()
                    .await
                    .get(&response.sp_hash)
                {
                    for (plot_identifier, candidate_pospace) in proofs {
                        if *plot_identifier == response.plot_identifier {
                            pospace = Some(candidate_pospace.clone());
                            break;
                        }
                    }
                } else {
                    debug!("Failed to load farmer proofs for {}", &response.sp_hash);
                    return Ok(());
                }
                if let Some(pospace) = pospace {
                    let include_taproot = pospace.pool_contract_puzzle_hash.is_some();
                    if let Some(computed_quality_string) = verify_and_get_quality_string(
                        &pospace,
                        self.constants,
                        response.challenge_hash,
                        response.sp_hash,
                        peak_height,
                    ) {
                        if is_sp_signatures {
                            let (challenge_chain_sp, challenge_chain_sp_harv_sig) =
                                &response.message_signatures[0];
                            let challenge_chain_sp_harv_sig =
                                challenge_chain_sp_harv_sig.try_into()?;
                            let (reward_chain_sp, reward_chain_sp_harv_sig) =
                                &response.message_signatures[1];
                            let reward_chain_sp_harv_sig = reward_chain_sp_harv_sig.try_into()?;
                            let local_pk = response.local_pk.into();
                            for (_, sk) in self.shared_state.farmer_private_keys.iter() {
                                let pk = sk.sk_to_pk();
                                if pk.to_bytes() == response.farmer_pk.bytes() {
                                    let agg_pk =
                                        generate_plot_public_key(&local_pk, &pk, include_taproot)?;
                                    if agg_pk.to_bytes() != pospace.plot_public_key.bytes() {
                                        warn!(
                                            "Key Mismatch {:?} != {:?}",
                                            pospace.plot_public_key, agg_pk
                                        );
                                        return Ok(());
                                    }
                                    let (taproot_share_cc_sp, taproot_share_rc_sp) =
                                        if include_taproot {
                                            let taproot_sk = generate_taproot_sk(&local_pk, &pk)?;
                                            (
                                                Some(sign_prepend(
                                                    &taproot_sk,
                                                    challenge_chain_sp.as_ref(),
                                                    &agg_pk,
                                                )),
                                                Some(sign_prepend(
                                                    &taproot_sk,
                                                    reward_chain_sp.as_ref(),
                                                    &agg_pk,
                                                )),
                                            )
                                        } else {
                                            (None, None)
                                        };
                                    let farmer_share_cc_sp =
                                        sign_prepend(sk, challenge_chain_sp.as_ref(), &agg_pk);
                                    let cc_sigs_to_agg =
                                        if let Some(taproot_share_cc_sp) = &taproot_share_cc_sp {
                                            vec![
                                                &challenge_chain_sp_harv_sig,
                                                &farmer_share_cc_sp,
                                                taproot_share_cc_sp,
                                            ]
                                        } else {
                                            vec![&challenge_chain_sp_harv_sig, &farmer_share_cc_sp]
                                        };
                                    let agg_sig_cc_sp =
                                        AggregateSignature::aggregate(&cc_sigs_to_agg, true)
                                            .map_err(|e| {
                                                Error::new(
                                                    ErrorKind::InvalidInput,
                                                    format!("{:?}", e),
                                                )
                                            })?;
                                    if agg_sig_cc_sp.to_signature().verify(
                                        true,
                                        challenge_chain_sp.as_ref(),
                                        AUG_SCHEME_DST,
                                        &agg_pk.to_bytes(),
                                        &agg_pk,
                                        true,
                                    ) != BLST_ERROR::BLST_SUCCESS
                                    {
                                        warn!(
                                            "Failed to validate cc signature {:?}",
                                            agg_sig_cc_sp.to_signature()
                                        );
                                        return Ok(());
                                    }

                                    let farmer_share_rc_sp =
                                        sign_prepend(sk, reward_chain_sp.as_ref(), &agg_pk);
                                    let rc_sigs_to_agg =
                                        if let Some(taproot_share_rc_sp) = &taproot_share_rc_sp {
                                            vec![
                                                &reward_chain_sp_harv_sig,
                                                &farmer_share_rc_sp,
                                                taproot_share_rc_sp,
                                            ]
                                        } else {
                                            vec![&reward_chain_sp_harv_sig, &farmer_share_rc_sp]
                                        };
                                    let agg_sig_rc_sp =
                                        AggregateSignature::aggregate(&rc_sigs_to_agg, true)
                                            .map_err(|e| {
                                                Error::new(
                                                    ErrorKind::InvalidInput,
                                                    format!("{:?}", e),
                                                )
                                            })?;
                                    if agg_sig_rc_sp.to_signature().verify(
                                        true,
                                        reward_chain_sp.as_ref(),
                                        AUG_SCHEME_DST,
                                        &agg_pk.to_bytes(),
                                        &agg_pk,
                                        true,
                                    ) != BLST_ERROR::BLST_SUCCESS
                                    {
                                        warn!(
                                            "Failed to validate rc signature {:?}",
                                            agg_sig_rc_sp.to_signature()
                                        );
                                        return Ok(());
                                    }
                                    let config = self.config.read().await;
                                    let (pool_target, pool_target_signature) = if let Some(
                                        pool_public_key,
                                    ) =
                                        &pospace.pool_public_key
                                    {
                                        if let Some(sk) =
                                            self.shared_state.pool_public_keys.get(pool_public_key)
                                        {
                                            let pool_target = PoolTarget {
                                                max_height: 0,
                                                puzzle_hash: Bytes32::from_str(
                                                    &parse_payout_address(&config.payout_address)?,
                                                )?,
                                            };
                                            let pool_target_signature =
                                                sign(sk, &pool_target.to_bytes(PROTOCOL_VERSION));
                                            (Some(pool_target), Some(pool_target_signature))
                                        } else {
                                            error!(
                                                "Don't have the private key for the pool key used by harvester: {pool_public_key}"
                                            );
                                            return Ok(());
                                        }
                                    } else {
                                        (None, None)
                                    };
                                    let request = DeclareProofOfSpace {
                                        challenge_hash: response.challenge_hash,
                                        challenge_chain_sp: *challenge_chain_sp,
                                        signage_point_index: sp_index,
                                        reward_chain_sp: *reward_chain_sp,
                                        proof_of_space: pospace.clone(),
                                        challenge_chain_sp_signature: agg_sig_cc_sp
                                            .to_signature()
                                            .to_bytes()
                                            .into(),
                                        reward_chain_sp_signature: agg_sig_rc_sp
                                            .to_signature()
                                            .to_bytes()
                                            .into(),
                                        farmer_puzzle_hash: if let Some(
                                            farmer_reward_address_override,
                                        ) =
                                            response.farmer_reward_address_override
                                        {
                                            farmer_reward_address_override
                                        } else {
                                            Bytes32::from_str(&parse_payout_address(
                                                &config.payout_address,
                                            )?)?
                                        },
                                        pool_target,
                                        pool_signature: pool_target_signature
                                            .map(|s| s.to_bytes().into()),
                                        include_signature_source_data: response
                                            .include_source_signature_data
                                            || response.farmer_reward_address_override.is_some(),
                                    };
                                    if let Some(client) = &*self.client.read().await {
                                        client
                                            .client
                                            .connection
                                            .write()
                                            .await
                                            .send(Message::Binary(
                                                ChiaMessage::new(
                                                    ProtocolMessageTypes::DeclareProofOfSpace,
                                                    PROTOCOL_VERSION,
                                                    &request,
                                                    None,
                                                )
                                                .to_bytes(PROTOCOL_VERSION)
                                                .into(),
                                            ))
                                            .await?;
                                        debug!("Declaring Proof of Space: {:?}", request);
                                        let top = format!("{:🌱<1$}", "", 43);
                                        let mid = format!(
                                            "{:🌱^1$}",
                                            "  Declaring New Proof of Space  ", 56
                                        );
                                        let bottom = format!("{:🌱<1$}", "", 43);
                                        info!("\n{top}\n{mid}\n{bottom}");
                                        if let Some(declared) = self
                                            .shared_state
                                            .metrics
                                            .read()
                                            .await
                                            .as_ref()
                                            .map(|v| &v.proofs_declared)
                                        {
                                            declared.inc();
                                        }
                                    } else {
                                        error!(
                                            "Failed to declare Proof of Space: {:?} No Client",
                                            request
                                        );
                                    }
                                }
                            }
                        } else if response.message_signatures.len() > 1 {
                            let (foliage_block_data_hash, foliage_sig_harvester) =
                                &response.message_signatures[0];
                            let foliage_sig_harvester = foliage_sig_harvester.try_into()?;
                            let (
                                foliage_transaction_block_hash,
                                foliage_transaction_block_sig_harvester,
                            ) = &response.message_signatures[1];
                            let foliage_transaction_block_sig_harvester =
                                foliage_transaction_block_sig_harvester.try_into()?;
                            let local_pk = response.local_pk.into();
                            for (_, sk) in self.shared_state.farmer_private_keys.iter() {
                                let pk = sk.sk_to_pk();
                                if pk.to_bytes() == response.farmer_pk.bytes() {
                                    let agg_pk =
                                        generate_plot_public_key(&local_pk, &pk, include_taproot)?;
                                    let (
                                        foliage_sig_taproot,
                                        foliage_transaction_block_sig_taproot,
                                    ) = if include_taproot {
                                        let taproot_sk = generate_taproot_sk(&local_pk, &pk)?;
                                        (
                                            Some(sign_prepend(
                                                &taproot_sk,
                                                foliage_block_data_hash.as_ref(),
                                                &agg_pk,
                                            )),
                                            Some(sign_prepend(
                                                &taproot_sk,
                                                foliage_transaction_block_hash.as_ref(),
                                                &agg_pk,
                                            )),
                                        )
                                    } else {
                                        (None, None)
                                    };
                                    let foliage_sig_farmer =
                                        sign_prepend(sk, foliage_block_data_hash.as_ref(), &agg_pk);
                                    let foliage_transaction_block_sig_farmer = sign_prepend(
                                        sk,
                                        foliage_transaction_block_hash.as_ref(),
                                        &agg_pk,
                                    );
                                    let foliage_sigs_to_agg =
                                        if let Some(foliage_sig_taproot) = &foliage_sig_taproot {
                                            vec![
                                                &foliage_sig_harvester,
                                                &foliage_sig_farmer,
                                                foliage_sig_taproot,
                                            ]
                                        } else {
                                            vec![&foliage_sig_harvester, &foliage_sig_farmer]
                                        };
                                    let foliage_agg_sig =
                                        AggregateSignature::aggregate(&foliage_sigs_to_agg, true)
                                            .map_err(|e| {
                                            Error::new(ErrorKind::InvalidInput, format!("{:?}", e))
                                        })?;

                                    let foliage_block_sigs_to_agg =
                                        if let Some(foliage_transaction_block_sig_taproot) =
                                            &foliage_transaction_block_sig_taproot
                                        {
                                            vec![
                                                &foliage_transaction_block_sig_harvester,
                                                &foliage_transaction_block_sig_farmer,
                                                foliage_transaction_block_sig_taproot,
                                            ]
                                        } else {
                                            vec![
                                                &foliage_transaction_block_sig_harvester,
                                                &foliage_transaction_block_sig_farmer,
                                            ]
                                        };
                                    let foliage_block_agg_sig = AggregateSignature::aggregate(
                                        &foliage_block_sigs_to_agg,
                                        true,
                                    )
                                    .map_err(|e| {
                                        Error::new(ErrorKind::InvalidInput, format!("{:?}", e))
                                    })?;
                                    if foliage_agg_sig.to_signature().verify(
                                        true,
                                        foliage_block_data_hash.as_ref(),
                                        AUG_SCHEME_DST,
                                        &agg_pk.to_bytes(),
                                        &agg_pk,
                                        true,
                                    ) != BLST_ERROR::BLST_SUCCESS
                                    {
                                        warn!(
                                            "Failed to validate foliage signature {:?}, Taproot Included: {include_taproot}, ",
                                            Bytes96::from(foliage_agg_sig.to_signature())
                                        );
                                        //return Ok(());
                                    }
                                    if foliage_block_agg_sig.to_signature().verify(
                                        true,
                                        foliage_transaction_block_hash.as_ref(),
                                        AUG_SCHEME_DST,
                                        &agg_pk.to_bytes(),
                                        &agg_pk,
                                        true,
                                    ) != BLST_ERROR::BLST_SUCCESS
                                    {
                                        warn!(
                                            "Failed to validate foliage_block signature {:?}, Taproot Included: {include_taproot}, ",
                                            Bytes96::from(foliage_block_agg_sig.to_signature())
                                        );
                                        //return Ok(());
                                    }
                                    let request = SignedValues {
                                        quality_string: computed_quality_string,
                                        foliage_block_data_signature: foliage_agg_sig
                                            .to_signature()
                                            .to_bytes()
                                            .into(),
                                        foliage_transaction_block_signature: foliage_block_agg_sig
                                            .to_signature()
                                            .to_bytes()
                                            .into(),
                                    };
                                    if let Some(client) = self.client.read().await.as_ref() {
                                        let _ = client
                                            .client
                                            .connection
                                            .write()
                                            .await
                                            .send(Message::Binary(
                                                ChiaMessage::new(
                                                    ProtocolMessageTypes::SignedValues,
                                                    PROTOCOL_VERSION,
                                                    &request,
                                                    None,
                                                )
                                                .to_bytes(PROTOCOL_VERSION)
                                                .into(),
                                            ))
                                            .await;
                                        debug!("Sending Signed Values: {:?}", request);
                                    } else {
                                        error!(
                                            "Failed to Sending Signed Values: {:?} No Client",
                                            request
                                        );
                                    }
                                }
                            }
                        } else {
                            warn!("No Signatures Received for {:?}", pospace);
                            return Ok(());
                        }
                    } else {
                        warn!("Have invalid PoSpace {:?}", pospace);
                        return Ok(());
                    }
                } else {
                    warn!("Failed to find Proof for {}", &response.sp_hash);
                    return Ok(());
                }
            }
        } else {
            error!("Do not have challenge hash {}", &response.challenge_hash);
        }
        Ok(())
    }
}
