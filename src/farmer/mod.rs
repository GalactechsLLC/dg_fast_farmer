use crate::farmer::config::Config;
use crate::farmer::protocols::fullnode::new_signage_point::NewSignagePointHandle;
use crate::farmer::protocols::fullnode::request_signed_values::RequestSignedValuesHandle;
use crate::harvesters::{load_harvesters, Harvesters};
use crate::tasks::pool_state_updater::FarmerPoolState;
use blst::min_pk::SecretKey;
use dg_xch_clients::api::pool::PoolClient;
use dg_xch_clients::protocols::farmer::NewSignagePoint;
use dg_xch_clients::protocols::ProtocolMessageTypes;
use dg_xch_clients::websocket::farmer::FarmerClient;
use dg_xch_clients::websocket::{
    ChiaMessageFilter, ChiaMessageHandler, ClientSSLConfig, Websocket,
};
use dg_xch_core::blockchain::proof_of_space::ProofOfSpace;
use dg_xch_core::blockchain::sized_bytes::{Bytes32, Bytes48};
use dg_xch_core::consensus::constants::{CONSENSUS_CONSTANTS_MAP, MAINNET};
use dg_xch_pos::plots::disk_plot::DiskPlot;
use dg_xch_pos::plots::plot_reader::PlotReader;
use log::{error, info};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::io::Error;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::fs::File;
use tokio::sync::Mutex;
use uuid::Uuid;

pub mod config;
pub mod protocols;

type ProofsMap = Arc<Mutex<HashMap<Bytes32, Vec<(String, ProofOfSpace)>>>>;
static PUBLIC_CRT: &str = "farmer/public_farmer.crt";
static PUBLIC_KEY: &str = "farmer/public_farmer.key";
static CA_PUBLIC_CRT: &str = "ca/chia_ca.crt";

#[derive(Clone)]
pub struct FarmerSharedState {
    pub(crate) signage_points: Arc<Mutex<HashMap<Bytes32, Vec<NewSignagePoint>>>>,
    pub(crate) quality_to_identifiers: Arc<Mutex<HashMap<Bytes32, FarmerIdentifier>>>,
    pub(crate) proofs_of_space: ProofsMap,
    pub(crate) cache_time: Arc<Mutex<HashMap<Bytes32, Instant>>>,
    pub(crate) pool_states: Arc<Mutex<HashMap<Bytes32, FarmerPoolState>>>,
    pub(crate) farmer_private_keys: Arc<HashMap<Bytes48, SecretKey>>,
    pub(crate) owner_secret_keys: Arc<HashMap<Bytes48, SecretKey>>,
    pub(crate) auth_secret_keys: Arc<HashMap<Bytes48, SecretKey>>,
    pub(crate) pool_public_keys: Arc<HashMap<Bytes48, SecretKey>>,
    pub(crate) config: Arc<Config>,
    pub(crate) run: Arc<AtomicBool>,
    pub(crate) force_pool_update: Arc<AtomicBool>,
    pub(crate) full_node_client: Arc<Mutex<Option<FarmerClient>>>,
    pub(crate) farmer_target: Arc<Bytes32>,
    pub(crate) pool_target: Arc<Bytes32>,
}

#[derive(Debug, Clone)]
pub struct PathInfo {
    pub path: PathBuf,
    pub file_name: String,
}
impl PathInfo {
    pub fn new(path: PathBuf) -> Self {
        let file_name = path
            .file_name()
            .map(|s| s.to_str().unwrap_or_default())
            .unwrap_or_default()
            .to_string();
        Self { path, file_name }
    }
}
impl Hash for PathInfo {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.file_name.hash(state)
    }
}
impl Eq for PathInfo {}
impl PartialEq for PathInfo {
    fn eq(&self, other: &Self) -> bool {
        self.file_name == other.file_name
    }
}

#[derive(Debug)]
pub struct PlotInfo {
    pub reader: PlotReader<File, DiskPlot<File>>,
    pub pool_public_key: Option<Bytes48>,
    pub pool_contract_puzzle_hash: Option<Bytes32>,
    pub plot_public_key: Bytes48,
    pub file_size: u64,
    pub time_modified: u64,
}

#[derive(Debug)]
pub struct FarmerIdentifier {
    pub plot_identifier: String,
    pub challenge_hash: Bytes32,
    pub sp_hash: Bytes32,
    pub harvester_id: Uuid,
}

pub struct Farmer<T: PoolClient + Sized + Sync + Send + 'static> {
    shared_state: Arc<FarmerSharedState>,
    harvesters: Arc<HashMap<Uuid, Arc<Harvesters>>>,
    pool_client: Arc<T>,
}
impl<T: PoolClient + Sized + Sync + Send> Farmer<T> {
    pub async fn new(
        shared_state: Arc<FarmerSharedState>,
        pool_client: Arc<T>,
    ) -> Result<Self, Error> {
        let harvesters =
            load_harvesters(shared_state.config.clone(), shared_state.run.clone()).await?;
        Ok(Self {
            shared_state,
            harvesters,
            pool_client,
        })
    }

    pub async fn run(self) {
        let s = self;
        'retry: loop {
            if !s.shared_state.run.load(Ordering::Relaxed) {
                break;
            }
            info!(
                "Starting Farmer FullNode Connection to: {}:{}",
                &s.shared_state.config.fullnode_host, s.shared_state.config.fullnode_port
            );
            loop {
                if !s.shared_state.run.load(Ordering::Relaxed) {
                    break;
                }
                match s.create_farmer_client(&s.shared_state).await {
                    Ok(mut c) => {
                        s.attach_client_handlers(&mut c).await;
                        info!("Farmer Client Initialized");
                        *s.shared_state.full_node_client.lock().await = Some(c);
                        break;
                    }
                    Err(e) => {
                        error!(
                            "Failed to Start Farmer Client, Waiting and trying again: {:?}",
                            e
                        );
                        tokio::time::sleep(Duration::from_secs(3)).await;
                        continue;
                    }
                }
            }
            let mut last_clear = Instant::now();
            loop {
                if let Some(client) = s.shared_state.full_node_client.lock().await.as_ref() {
                    if client.is_closed() {
                        if !s.shared_state.run.load(Ordering::Relaxed) {
                            info!("Farmer Stopped");
                            break 'retry;
                        } else {
                            info!("Unexpected Farmer Client Closed, Reconnecting");
                            break;
                        }
                    }
                }
                if last_clear.elapsed() > Duration::from_secs(300) {
                    let expired: Vec<Bytes32> = s
                        .shared_state
                        .cache_time
                        .lock()
                        .await
                        .iter()
                        .filter_map(|(k, v)| {
                            if v.elapsed() > Duration::from_secs(3600) {
                                Some(*k)
                            } else {
                                None
                            }
                        })
                        .collect();
                    s.shared_state
                        .cache_time
                        .lock()
                        .await
                        .retain(|k, _| !expired.contains(k));
                    s.shared_state
                        .signage_points
                        .lock()
                        .await
                        .retain(|k, _| !expired.contains(k));
                    s.shared_state
                        .quality_to_identifiers
                        .lock()
                        .await
                        .retain(|k, _| !expired.contains(k));
                    s.shared_state
                        .proofs_of_space
                        .lock()
                        .await
                        .retain(|k, _| !expired.contains(k));
                    last_clear = Instant::now();
                }
                if !s.shared_state.run.load(Ordering::Relaxed) {
                    info!("Farmer Stopping");
                    break 'retry;
                }
                tokio::time::sleep(Duration::from_secs(5)).await;
            }
        }
    }

    async fn create_farmer_client(
        &self,
        shared_state: &FarmerSharedState,
    ) -> Result<FarmerClient, Error> {
        let network_id = shared_state.config.selected_network.as_str();
        if let Some(ssl_root_path) = &shared_state.config.ssl_root_path {
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
    }

    async fn attach_client_handlers(&self, client: &mut FarmerClient) {
        client.client.lock().await.clear().await;
        let signage_handle_id = Uuid::new_v4();
        client
            .client
            .lock()
            .await
            .subscribe(
                signage_handle_id,
                ChiaMessageHandler::new(
                    ChiaMessageFilter {
                        msg_type: Some(ProtocolMessageTypes::NewSignagePoint),
                        id: None,
                    },
                    Arc::new(NewSignagePointHandle {
                        id: signage_handle_id,
                        shared_state: self.shared_state.clone(),
                        pool_state: self.shared_state.pool_states.clone(),
                        pool_client: self.pool_client.clone(),
                        signage_points: self.shared_state.signage_points.clone(),
                        cache_time: self.shared_state.cache_time.clone(),
                        harvesters: self.harvesters.clone(),
                        constants: CONSENSUS_CONSTANTS_MAP
                            .get(&self.shared_state.config.selected_network)
                            .unwrap_or(&MAINNET),
                    }),
                ),
            )
            .await;
        let request_signed_values_id = Uuid::new_v4();
        client
            .client
            .lock()
            .await
            .subscribe(
                request_signed_values_id,
                ChiaMessageHandler::new(
                    ChiaMessageFilter {
                        msg_type: Some(ProtocolMessageTypes::RequestSignedValues),
                        id: None,
                    },
                    Arc::new(RequestSignedValuesHandle {
                        id: request_signed_values_id,
                        shared_state: self.shared_state.clone(),
                        pool_client: self.pool_client.clone(),
                        harvesters: self.harvesters.clone(),
                        constants: CONSENSUS_CONSTANTS_MAP
                            .get(&self.shared_state.config.selected_network)
                            .unwrap_or(&MAINNET),
                    }),
                ),
            )
            .await;
    }
}
