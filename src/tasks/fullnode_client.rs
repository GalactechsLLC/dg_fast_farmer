use std::collections::HashMap;
use std::io::{Cursor, Error, ErrorKind};
use std::sync::{Arc};
use std::sync::atomic::{Ordering};
use std::time::{Duration, Instant};
use async_trait::async_trait;
use log::{debug, error, info, warn};
use tokio::sync::mpsc::Sender;
use tokio::sync::Mutex;
use uuid::Uuid;
use dg_xch_clients::protocols::farmer::{NewSignagePoint, RequestSignedValues};
use dg_xch_clients::protocols::harvester::{PoolDifficulty, RequestSignatures};
use dg_xch_clients::protocols::ProtocolMessageTypes;
use dg_xch_clients::websocket::{ChiaMessage, ChiaMessageFilter, ChiaMessageHandler, ClientSSLConfig, MessageHandler, Websocket};
use dg_xch_clients::websocket::farmer::FarmerClient;
use dg_xch_core::blockchain::sized_bytes::{Bytes32};
use dg_xch_core::consensus::pot_iterations::POOL_SUB_SLOT_ITERS;
use dg_xch_serialize::ChiaSerialize;
use crate::models::{FarmerIdentifier, FarmerSharedState};
use crate::tasks::pool_state_updater::FarmerPoolState;
use crate::tasks::signatures_handler::{handle_request_signed_values};

static PUBLIC_CRT: &str = "farmer/public_farmer.crt";
static PUBLIC_KEY: &str = "farmer/public_farmer.key";
static CA_PUBLIC_CRT: &str = "ca/chia_ca.crt";

pub async fn client_handler(
    shared_state: Arc<FarmerSharedState>,
    signage_sender: Sender<(NewSignagePoint, Vec<PoolDifficulty>)>,
) {
    let pool_state = Arc::new(Mutex::new(HashMap::new()));
    let signage_points = Arc::new(Mutex::new(HashMap::new()));
    'retry: loop {
        if !shared_state.run.load(Ordering::Relaxed) {
            break;
        }
        info!("Starting Farmer Client: {}:{}", &shared_state.config.fullnode_host, shared_state.config.fullnode_port);
        let network_id = shared_state.config.selected_network.as_str();
        loop {
            let fnc = match if let Some(ssl_root_path) = &shared_state.config.ssl_root_path {
                FarmerClient::new_ssl(
                    &shared_state.config.fullnode_host,
                    shared_state.config.fullnode_port,
                    ClientSSLConfig {
                        ssl_crt_path: format!("{}/{}", ssl_root_path, PUBLIC_CRT).as_str(),
                        ssl_key_path: format!("{}/{}", ssl_root_path, PUBLIC_KEY).as_str(),
                        ssl_ca_crt_path: format!("{}/{}", ssl_root_path, CA_PUBLIC_CRT).as_str(),
                    },
                    network_id,
                    &None,
                    shared_state.run.clone(),
                )
                    .await
            } else {
                FarmerClient::new_ssl_generate(
                    &shared_state.config.fullnode_host,
                    shared_state.config.fullnode_port,
                    network_id,
                    &None,
                    shared_state.run.clone(),
                )
                    .await
            }
            {
                Ok(c) => Some(c),
                Err(e) => {
                    error!(
                        "Failed to Start Farmer Client, Waiting and trying again: {:?}",
                        e
                    );
                    tokio::time::sleep(Duration::from_secs(3)).await;
                    if !shared_state.run.load(Ordering::Relaxed) {
                        break;
                    }
                    continue;
                }
            };
            if fnc.is_some() {
                {
                    let mut client = fnc.as_ref()
                        .expect("Client was checked above, Should have existed").client.lock().await;
                    client.clear().await;
                    let signage_handle_id = Uuid::new_v4();
                    client
                        .subscribe(
                            signage_handle_id,
                            ChiaMessageHandler::new(
                                ChiaMessageFilter {
                                    msg_type: Some(ProtocolMessageTypes::NewSignagePoint),
                                    id: None,
                                },
                                Arc::new(NewSignagePointHandle {
                                    id: signage_handle_id,
                                    quality_to_identifiers: shared_state.quality_to_identifiers.clone(),
                                    pool_state: pool_state.clone(),
                                    signage_points: signage_points.clone(),
                                    cache_time: Arc::new(Default::default()),
                                    signage_sender: Arc::new(signage_sender.clone()),
                                }),
                            ),
                        )
                        .await;
                    let request_signed_values_id = Uuid::new_v4();
                    client
                        .subscribe(
                            request_signed_values_id,
                            ChiaMessageHandler::new(
                                ChiaMessageFilter {
                                    msg_type: Some(ProtocolMessageTypes::RequestSignedValues),
                                    id: None,
                                },
                                Arc::new(RequestSignedValuesHandle {
                                    id: request_signed_values_id,
                                    shared_state: shared_state.clone()
                                }),
                            ),
                        )
                        .await;
                }
                info!("Farmer Client Initialized");
                *shared_state.full_node_client.lock().await = fnc;
                break;
            } else {
                error!("Failed to Initialize Farmer Client");
                continue;
            }
        }
        loop {
            if let Some(client) = shared_state.full_node_client.lock().await.as_ref() {
                if client.is_closed() {
                    if !shared_state.run.load(Ordering::Relaxed) {
                        info!("Farmer Stopped");
                        break 'retry;
                    } else {
                        info!("Unexpected Farmer Client Closed, Reconnecting");
                        break;
                    }
                }
            }
            if !shared_state.run.load(Ordering::Relaxed) {
                info!("Farmer Stopping");
                break 'retry;
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
        if !shared_state.run.load(Ordering::Relaxed) {
            info!("Farmer Stopping");
            break 'retry;
        }
    }
}

pub struct RequestSignedValuesHandle {
    pub id: Uuid,
    pub shared_state: Arc<FarmerSharedState>
}
#[async_trait]
impl MessageHandler for RequestSignedValuesHandle {
    async fn handle(&self, msg: Arc<ChiaMessage>) -> Result<(), Error> {
        let mut cursor = Cursor::new(&msg.data);
        let request = RequestSignedValues::from_bytes(&mut cursor)?;
        if let Some(identifier) = self
            .shared_state
            .quality_to_identifiers
            .lock()
            .await
            .get(&request.quality_string)
        {
            handle_request_signed_values(RequestSignatures{
                plot_identifier: identifier.plot_identifier.clone(),
                challenge_hash: identifier.challenge_hash,
                sp_hash: identifier.sp_hash,
                messages: vec![
                    request.foliage_block_data_hash,
                    request.foliage_transaction_block_hash,
                ],
            }, self.shared_state.clone()).await
        } else {
            error!("Do not have quality {}", &request.quality_string);
            Err(Error::new(
                ErrorKind::NotFound,
                format!("Do not have quality {}", &request.quality_string),
            ))
        }
    }
}

pub struct NewSignagePointHandle {
    pub id: Uuid,
    pub pool_state: Arc<Mutex<HashMap<Bytes32, FarmerPoolState>>>,
    pub signage_points: Arc<Mutex<HashMap<Bytes32, Vec<NewSignagePoint>>>>,
    pub cache_time: Arc<Mutex<HashMap<Bytes32, Instant>>>,
    pub signage_sender: Arc<Sender<(NewSignagePoint, Vec<PoolDifficulty>)>>,
    pub quality_to_identifiers: Arc<Mutex<HashMap<Bytes32, FarmerIdentifier>>>,
}
#[async_trait]
impl MessageHandler for NewSignagePointHandle {
    async fn handle(&self, msg: Arc<ChiaMessage>) -> Result<(), Error> {
        let mut cursor = Cursor::new(&msg.data);
        let sp = NewSignagePoint::from_bytes(&mut cursor)?;
        let mut pool_difficulties = vec![];
        for (p2_singleton_puzzle_hash, pool_dict) in self.pool_state.lock().await.iter() {
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
                        pool_contract_puzzle_hash: p2_singleton_puzzle_hash.clone(),
                    })
                } else {
                    warn!("No pool specific difficulty has been set for {p2_singleton_puzzle_hash}, check communication with the pool, skipping this signage point, pool: {}", &config.pool_url);
                    continue;
                }
            }
        }
        info!(
            "New Signage Point({}): {:?}",
            sp.signage_point_index, sp.challenge_hash
        );
        let _ = self.signage_sender.send((sp, pool_difficulties)).await;
        Ok(())
    }
}