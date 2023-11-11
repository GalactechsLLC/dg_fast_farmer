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
use dg_xch_core::blockchain::sized_bytes::{Bytes32, Bytes48, SizedBytes};
use dg_xch_core::consensus::constants::{CONSENSUS_CONSTANTS_MAP, MAINNET};
use dg_xch_pos::plots::disk_plot::DiskPlot;
use dg_xch_pos::plots::plot_reader::PlotReader;
use log::{error, info};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::io::Error;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use dg_xch_core::ssl::create_all_ssl;
use dg_xch_serialize::hash_256;
use tokio::fs::File;
use tokio::sync::Mutex;
use uuid::Uuid;
use crate::get_ssl_root_path;

pub mod config;
pub mod protocols;

type ProofsMap = Arc<Mutex<HashMap<Bytes32, Vec<(String, ProofOfSpace)>>>>;
static PUBLIC_CRT: &str = "farmer/public_farmer.crt";
static PUBLIC_KEY: &str = "farmer/public_farmer.key";
static CA_PUBLIC_CRT: &str = "ca/chia_ca.crt";

#[derive(Clone, Default)]
pub struct GuiStats {
    pub keys: Vec<Bytes48>,
    pub most_recent_sp: (Bytes32, u8),
    pub total_plot_count: u64,
    pub total_plot_space: u64,
    pub last_pool_update: u64,
}

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
    pub(crate) gui_stats: Arc<Mutex<GuiStats>>,
    pub(crate) last_sp_timestamp: Arc<Mutex<Instant>>,
}
impl Default for FarmerSharedState {
    fn default() -> Self {
        Self {
            signage_points: Default::default(),
            quality_to_identifiers: Arc::new(Default::default()),
            proofs_of_space: Arc::new(Default::default()),
            cache_time: Arc::new(Default::default()),
            pool_states: Arc::new(Default::default()),
            farmer_private_keys: Arc::new(Default::default()),
            owner_secret_keys: Arc::new(Default::default()),
            auth_secret_keys: Arc::new(Default::default()),
            pool_public_keys: Arc::new(Default::default()),
            config: Arc::new(Default::default()),
            run: Arc::new(Default::default()),
            force_pool_update: Arc::new(Default::default()),
            full_node_client: Arc::new(Default::default()),
            farmer_target: Arc::new(Default::default()),
            pool_target: Arc::new(Default::default()),
            gui_stats: Arc::new(Default::default()),
            last_sp_timestamp: Arc::new(Mutex::new(Instant::now()))
        }
    }
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
        let harvesters = load_harvesters(shared_state.clone()).await?;
        Ok(Self {
            shared_state,
            harvesters,
            pool_client,
        })
    }

    pub async fn run(self) {
        let s = self;
        let mut client_run = Arc::new(AtomicBool::new(true));
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
                if let Some(client) = s.shared_state.full_node_client.lock().await.as_ref() {
                    client_run.store(false, Ordering::Relaxed);
                    client.client.lock().await.shutdown().await.unwrap_or_default();
                }
                client_run = Arc::new(AtomicBool::new(true));
                match s.create_farmer_client(&s.shared_state, client_run.clone()).await {
                    Ok(mut c) => {
                        if let Err(e) = s.attach_client_handlers(&s.shared_state, &mut c).await {
                            error!("Failed to attach socket listeners: {:?}", e);
                            continue;
                        } else {
                            info!("Farmer Client Initialized");
                            *s.shared_state.full_node_client.lock().await = Some(c);
                            break;
                        }
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
                let dur = Instant::now()
                        .duration_since(*s.shared_state.last_sp_timestamp.lock().await)
                        .as_secs();
                if dur >= 180 {
                    info!(
                        "Failed to get Signage Point after {dur} seconds, restarting farmer client"
                    );
                    *s.shared_state.last_sp_timestamp.lock().await = Instant::now();
                    if let Some(c) = &*s.shared_state.full_node_client.lock().await {
                        info!("Shutting Down old Farmer Client: {}:{}", s.shared_state.config.fullnode_host, s.shared_state.config.fullnode_host);
                        client_run.store(false, Ordering::Relaxed);
                        c.client.lock().await.shutdown().await.unwrap_or_default();
                        break;
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
                            if v.elapsed() > Duration::from_secs(1800) {
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
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    }

    async fn create_farmer_client(
        &self,
        shared_state: &FarmerSharedState,
        client_run: Arc<AtomicBool>,
    ) -> Result<FarmerClient, Error> {
        let network_id = shared_state.config.selected_network.as_str();
        let ssl_path = get_ssl_root_path(shared_state);
        create_all_ssl(&ssl_path, false)?;
        FarmerClient::new_ssl(
            &shared_state.config.fullnode_host,
            shared_state.config.fullnode_port,
            ClientSSLConfig {
                ssl_crt_path: &ssl_path.join(PUBLIC_CRT).to_string_lossy(),
                ssl_key_path: &ssl_path.join(PUBLIC_KEY).to_string_lossy(),
                ssl_ca_crt_path: &ssl_path.join(CA_PUBLIC_CRT).to_string_lossy(),
            },
            network_id,
            &None,
            client_run.clone(),
        )
            .await
    }

    async fn attach_client_handlers(&self, shared_state: &FarmerSharedState, client: &mut FarmerClient) -> Result<(), Error>{
        client.client.lock().await.clear().await;
        let signage_handle_id = Uuid::new_v4();
        let harvester_id = load_client_id(shared_state).await?;
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
                        harvester_id,
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
        Ok(())
    }
}


static HARVESTER_CRT: &'static str = "harvester/private_harvester.crt";

async fn load_client_id(shared_state: &FarmerSharedState) -> Result<Bytes32, Error>{
    let ssl_path = get_ssl_root_path(shared_state).join(Path::new(HARVESTER_CRT));
    let cert = tokio::fs::read_to_string(ssl_path).await?;
    Ok(Bytes32::new(&hash_256(&cert)))
}