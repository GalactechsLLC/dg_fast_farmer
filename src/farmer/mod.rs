use crate::cli::get_ssl_root_path;
use crate::farmer::config::Config;
use crate::farmer::protocols::fullnode::new_signage_point::NewSignagePointHandle;
use crate::farmer::protocols::fullnode::request_signed_values::RequestSignedValuesHandle;
use crate::harvesters::{load_harvesters, Harvesters};
use dg_xch_clients::api::pool::PoolClient;
use dg_xch_clients::websocket::farmer::FarmerClient;
use dg_xch_clients::websocket::WsClientConfig;
use dg_xch_clients::ClientSSLConfig;
use dg_xch_core::blockchain::sized_bytes::{Bytes32, Bytes48, SizedBytes};
use dg_xch_core::consensus::constants::{CONSENSUS_CONSTANTS_MAP, MAINNET};
use dg_xch_core::protocols::farmer::FarmerSharedState;
use dg_xch_core::protocols::{ChiaMessageFilter, ChiaMessageHandler, ProtocolMessageTypes};
use dg_xch_core::ssl::create_all_ssl;
use dg_xch_pos::plots::disk_plot::DiskPlot;
use dg_xch_pos::plots::plot_reader::PlotReader;
use dg_xch_serialize::hash_256;
use log::{error, info};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::io::Error;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::fs::File;
use tokio::sync::Mutex;
use uuid::Uuid;

pub mod config;
pub mod protocols;

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
pub struct ExtendedFarmerSharedState {
    pub(crate) config: Arc<Config>,
    pub(crate) run: Arc<AtomicBool>,
    pub(crate) force_pool_update: Arc<AtomicBool>,
    pub(crate) full_node_client: Arc<Mutex<Option<FarmerClient<ExtendedFarmerSharedState>>>>,
    pub(crate) gui_stats: Arc<Mutex<GuiStats>>,
    pub(crate) last_sp_timestamp: Arc<Mutex<Instant>>,
}
impl Default for ExtendedFarmerSharedState {
    fn default() -> Self {
        Self {
            config: Arc::new(Default::default()),
            run: Arc::new(Default::default()),
            force_pool_update: Arc::new(Default::default()),
            full_node_client: Arc::new(Default::default()),
            gui_stats: Arc::new(Default::default()),
            last_sp_timestamp: Arc::new(Mutex::new(Instant::now())),
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

pub struct Farmer<T: PoolClient + Sized + Sync + Send + 'static> {
    shared_state: Arc<FarmerSharedState<ExtendedFarmerSharedState>>,
    harvesters: Arc<HashMap<Bytes32, Arc<Harvesters>>>,
    pool_client: Arc<T>,
}
impl<T: PoolClient + Sized + Sync + Send> Farmer<T> {
    pub async fn new(
        shared_state: Arc<FarmerSharedState<ExtendedFarmerSharedState>>,
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
            if !s.shared_state.data.run.load(Ordering::Relaxed) {
                break;
            }
            info!(
                "Starting Farmer FullNode Connection to: {}:{}",
                &s.shared_state.data.config.fullnode_ws_host,
                s.shared_state.data.config.fullnode_ws_port
            );
            loop {
                if !s.shared_state.data.run.load(Ordering::Relaxed) {
                    break;
                }
                if let Some(client) = s.shared_state.data.full_node_client.lock().await.as_ref() {
                    client_run.store(false, Ordering::Relaxed);
                    client
                        .client
                        .connection
                        .lock()
                        .await
                        .shutdown()
                        .await
                        .unwrap_or_default();
                }
                client_run = Arc::new(AtomicBool::new(true));
                match s
                    .create_farmer_client(s.shared_state.clone(), client_run.clone())
                    .await
                {
                    Ok(mut c) => {
                        if let Err(e) = s.attach_client_handlers(&s.shared_state, &mut c).await {
                            error!("Failed to attach socket listeners: {:?}", e);
                            continue;
                        } else {
                            info!("Farmer Client Initialized");
                            *s.shared_state.data.full_node_client.lock().await = Some(c);
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
                if let Some(client) = s.shared_state.data.full_node_client.lock().await.as_ref() {
                    if client.is_closed() {
                        if !s.shared_state.data.run.load(Ordering::Relaxed) {
                            info!("Farmer Stopped");
                            break 'retry;
                        } else {
                            info!("Unexpected Farmer Client Closed, Reconnecting");
                            break;
                        }
                    }
                }
                let dur = Instant::now()
                    .duration_since(*s.shared_state.data.last_sp_timestamp.lock().await)
                    .as_secs();
                if dur >= 180 {
                    info!(
                        "Failed to get Signage Point after {dur} seconds, restarting farmer client"
                    );
                    *s.shared_state.data.last_sp_timestamp.lock().await = Instant::now();
                    if let Some(c) = &*s.shared_state.data.full_node_client.lock().await {
                        info!(
                            "Shutting Down old Farmer Client: {}:{}",
                            s.shared_state.data.config.fullnode_ws_host,
                            s.shared_state.data.config.fullnode_ws_host
                        );
                        client_run.store(false, Ordering::Relaxed);
                        c.client
                            .connection
                            .lock()
                            .await
                            .shutdown()
                            .await
                            .unwrap_or_default();
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
                if !s.shared_state.data.run.load(Ordering::Relaxed) {
                    info!("Farmer Stopping");
                    break 'retry;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }
    }

    async fn create_farmer_client(
        &self,
        shared_state: Arc<FarmerSharedState<ExtendedFarmerSharedState>>,
        client_run: Arc<AtomicBool>,
    ) -> Result<FarmerClient<ExtendedFarmerSharedState>, Error> {
        let network_id = shared_state.data.config.selected_network.clone();
        let ssl_path = get_ssl_root_path(shared_state.as_ref());
        create_all_ssl(&ssl_path, false)?;
        FarmerClient::new(
            Arc::new(WsClientConfig {
                host: shared_state.data.config.fullnode_ws_host.clone(),
                port: shared_state.data.config.fullnode_ws_port,
                network_id,
                ssl_info: Some(ClientSSLConfig {
                    ssl_crt_path: ssl_path.join(PUBLIC_CRT).to_string_lossy().to_string(),
                    ssl_key_path: ssl_path.join(PUBLIC_KEY).to_string_lossy().to_string(),
                    ssl_ca_crt_path: ssl_path.join(CA_PUBLIC_CRT).to_string_lossy().to_string(),
                }),
                software_version: None,
                additional_headers: None,
            }),
            shared_state.clone(),
            client_run.clone(),
        )
        .await
    }

    async fn attach_client_handlers(
        &self,
        shared_state: &FarmerSharedState<ExtendedFarmerSharedState>,
        client: &mut FarmerClient<ExtendedFarmerSharedState>,
    ) -> Result<(), Error> {
        client.client.connection.lock().await.clear().await;
        let signage_handle_id = Uuid::new_v4();
        let harvester_id = load_client_id(shared_state).await?;
        client
            .client
            .connection
            .lock()
            .await
            .subscribe(
                signage_handle_id,
                ChiaMessageHandler::new(
                    NEW_SIGNAGE_POINT_FILTER.clone(),
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
                            .get(&self.shared_state.data.config.selected_network)
                            .unwrap_or(&MAINNET),
                    }),
                ),
            )
            .await;
        let request_signed_values_id = Uuid::new_v4();
        client
            .client
            .connection
            .lock()
            .await
            .subscribe(
                request_signed_values_id,
                ChiaMessageHandler::new(
                    SIGNED_VALUES_FILTER.clone(),
                    Arc::new(RequestSignedValuesHandle {
                        id: request_signed_values_id,
                        shared_state: self.shared_state.clone(),
                        pool_client: self.pool_client.clone(),
                        harvesters: self.harvesters.clone(),
                        constants: CONSENSUS_CONSTANTS_MAP
                            .get(&self.shared_state.data.config.selected_network)
                            .unwrap_or(&MAINNET),
                    }),
                ),
            )
            .await;
        Ok(())
    }
}

static HARVESTER_CRT: &str = "harvester/private_harvester.crt";
static NEW_SIGNAGE_POINT_FILTER: Lazy<Arc<ChiaMessageFilter>> = Lazy::new(|| {
    Arc::new(ChiaMessageFilter {
        msg_type: Some(ProtocolMessageTypes::NewSignagePoint),
        id: None,
    })
});
static SIGNED_VALUES_FILTER: Lazy<Arc<ChiaMessageFilter>> = Lazy::new(|| {
    Arc::new(ChiaMessageFilter {
        msg_type: Some(ProtocolMessageTypes::RequestSignedValues),
        id: None,
    })
});

async fn load_client_id(
    shared_state: &FarmerSharedState<ExtendedFarmerSharedState>,
) -> Result<Bytes32, Error> {
    let ssl_path = get_ssl_root_path(shared_state).join(Path::new(HARVESTER_CRT));
    let cert = tokio::fs::read_to_string(ssl_path).await?;
    Ok(Bytes32::new(&hash_256(cert)))
}
