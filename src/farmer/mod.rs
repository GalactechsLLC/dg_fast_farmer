use crate::PROTOCOL_VERSION;
use crate::cli::utils::{get_ssl_root_path, load_client_id};
use crate::farmer::config::Config;
use crate::farmer::protocols::fullnode::new_signage_point::NewSignagePointHandle;
use crate::farmer::protocols::fullnode::request_signed_values::RequestSignedValuesHandle;
use crate::gui::FullNodeState;
use crate::harvesters::{Harvesters, load_harvesters};
use crate::metrics::Metrics;
use dg_xch_clients::ClientSSLConfig;
use dg_xch_clients::api::pool::PoolClient;
use dg_xch_clients::websocket::WsClientConfig;
use dg_xch_clients::websocket::farmer::FarmerClient;
use dg_xch_core::blockchain::sized_bytes::{Bytes32, Bytes48};
use dg_xch_core::consensus::constants::{CONSENSUS_CONSTANTS_MAP, MAINNET};
use dg_xch_core::protocols::farmer::FarmerSharedState;
use dg_xch_core::protocols::{ChiaMessageFilter, ChiaMessageHandler, ProtocolMessageTypes};
use dg_xch_core::ssl::create_all_ssl;
use dg_xch_pos::plots::disk_plot::DiskPlot;
use dg_xch_pos::plots::plot_reader::PlotReader;
use log::{error, info};
use once_cell::sync::Lazy;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::io::Error;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::fs::File;
use tokio::sync::RwLock;
use uuid::Uuid;

pub mod config;
pub mod protocols;

pub static PUBLIC_CRT: &str = "farmer/public_farmer.crt";
pub static PUBLIC_KEY: &str = "farmer/public_farmer.key";
pub static CA_PUBLIC_CRT: &str = "ca/chia_ca.crt";
pub static PRIVATE_CRT: &str = "farmer/private_farmer.crt";
pub static PRIVATE_KEY: &str = "farmer/private_farmer.key";
pub static CA_PRIVATE_CRT: &str = "ca/private_ca.crt";

pub static HARVESTER_CRT: &str = "harvester/private_harvester.crt";

#[derive(Clone, Default)]
pub struct PlotCounts {
    pub og_plot_count: Arc<AtomicU64>,
    pub nft_plot_count: Arc<AtomicU64>,
    pub compresses_plot_count: Arc<AtomicU64>,
    pub invalid_plot_count: Arc<AtomicU64>,
    pub total_plot_space: Arc<AtomicU64>,
}

#[derive(Clone)]
pub struct ExtendedFarmerSharedState {
    pub config: Arc<RwLock<Arc<Config>>>,
    pub run: Arc<AtomicBool>,
    pub force_pool_update: Arc<AtomicBool>,
    pub full_node_client: Arc<RwLock<Option<FarmerClient<ExtendedFarmerSharedState>>>>,
    pub last_sp_timestamp: Arc<RwLock<Instant>>,
    pub extended_metrics: Arc<Metrics>,
    pub fullnode_state: Arc<RwLock<Option<FullNodeState>>>,
    pub additional_headers: Arc<HashMap<String, String>>,
    pub plot_counts: Arc<PlotCounts>,
    pub most_recent_sp: Arc<RwLock<(Bytes32, u8)>>,
    pub last_pool_update: Arc<AtomicU64>,
    pub missing_farmer_keys: Arc<RwLock<HashSet<Bytes48>>>,
    pub missing_plotnft_info: Arc<RwLock<HashMap<Bytes32, Bytes48>>>,
}
impl Default for ExtendedFarmerSharedState {
    fn default() -> Self {
        Self {
            config: Arc::new(Default::default()),
            run: Arc::new(Default::default()),
            force_pool_update: Arc::new(Default::default()),
            full_node_client: Arc::new(Default::default()),
            last_sp_timestamp: Arc::new(RwLock::new(Instant::now())),
            extended_metrics: Arc::new(Default::default()),
            fullnode_state: Arc::new(Default::default()),
            additional_headers: Arc::new(Default::default()),
            plot_counts: Arc::new(Default::default()),
            most_recent_sp: Arc::new(Default::default()),
            last_pool_update: Arc::new(Default::default()),
            missing_farmer_keys: Arc::new(Default::default()),
            missing_plotnft_info: Arc::new(Default::default()),
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
            let config = s.shared_state.data.config.read().await.clone();
            info!(
                "Starting Farmer FullNode Connection to: {}:{}",
                &config.fullnode_ws_host, config.fullnode_ws_port
            );
            loop {
                if !s.shared_state.data.run.load(Ordering::Relaxed) {
                    break;
                }
                if let Some(client) = s.shared_state.data.full_node_client.read().await.as_ref() {
                    client_run.store(false, Ordering::Relaxed);
                    client
                        .client
                        .connection
                        .write()
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
                        if let Some(handshake) = &c.client.handshake {
                            info!(
                                "Using node with Upstream Version: {}",
                                handshake.software_version
                            );
                        } else {
                            error!("Failed to read chia version from client handshake");
                        }
                        if let Err(e) = s.attach_client_handlers(&s.shared_state, &mut c).await {
                            error!("Failed to attach socket listeners: {:?}", e);
                            continue;
                        } else {
                            info!("Farmer Client Initialized");
                            *s.shared_state.data.full_node_client.write().await = Some(c);
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
                if let Some(client) = s.shared_state.data.full_node_client.read().await.as_ref() {
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
                    .duration_since(*s.shared_state.data.last_sp_timestamp.read().await)
                    .as_secs();
                if dur >= 60 {
                    info!(
                        "Failed to get Signage Point after {dur} seconds, restarting farmer client"
                    );
                    *s.shared_state.data.last_sp_timestamp.write().await = Instant::now();
                    if let Some(c) = &*s.shared_state.data.full_node_client.read().await {
                        info!(
                            "Shutting Down old Farmer Client: {}:{}",
                            &config.fullnode_ws_host, config.fullnode_ws_port
                        );
                        client_run.store(false, Ordering::Relaxed);
                        c.client
                            .connection
                            .write()
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
                        .write()
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
                        .write()
                        .await
                        .retain(|k, _| !expired.contains(k));
                    s.shared_state
                        .signage_points
                        .write()
                        .await
                        .retain(|k, _| !expired.contains(k));
                    s.shared_state
                        .quality_to_identifiers
                        .write()
                        .await
                        .retain(|k, _| !expired.contains(k));
                    s.shared_state
                        .proofs_of_space
                        .write()
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
        let config = shared_state.data.config.read().await.clone();
        let network_id = config.selected_network.clone();
        let ssl_path = get_ssl_root_path(config.as_ref());
        create_all_ssl(&ssl_path, false)?;
        FarmerClient::new(
            Arc::new(WsClientConfig {
                host: config.fullnode_ws_host.clone(),
                port: config.fullnode_ws_port,
                network_id,
                ssl_info: Some(ClientSSLConfig {
                    ssl_crt_path: ssl_path.join(PUBLIC_CRT).to_string_lossy().to_string(),
                    ssl_key_path: ssl_path.join(PUBLIC_KEY).to_string_lossy().to_string(),
                    ssl_ca_crt_path: ssl_path.join(CA_PUBLIC_CRT).to_string_lossy().to_string(),
                }),
                software_version: None,
                protocol_version: PROTOCOL_VERSION,
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
        let config = shared_state.data.config.read().await.clone();
        client.client.connection.write().await.clear().await;
        let signage_handle_id = Uuid::new_v4();
        let harvester_id = load_client_id(shared_state).await?;
        client
            .client
            .connection
            .write()
            .await
            .subscribe(
                signage_handle_id,
                Arc::new(ChiaMessageHandler::new(
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
                            .get(&config.selected_network)
                            .unwrap_or(&MAINNET),
                    }),
                )),
            )
            .await;
        let request_signed_values_id = Uuid::new_v4();
        client
            .client
            .connection
            .write()
            .await
            .subscribe(
                request_signed_values_id,
                Arc::new(ChiaMessageHandler::new(
                    SIGNED_VALUES_FILTER.clone(),
                    Arc::new(RequestSignedValuesHandle {
                        id: request_signed_values_id,
                        shared_state: self.shared_state.clone(),
                        pool_client: self.pool_client.clone(),
                        harvesters: self.harvesters.clone(),
                        constants: CONSENSUS_CONSTANTS_MAP
                            .get(&config.selected_network)
                            .unwrap_or(&MAINNET),
                    }),
                )),
            )
            .await;
        Ok(())
    }
}
static NEW_SIGNAGE_POINT_FILTER: Lazy<Arc<ChiaMessageFilter>> = Lazy::new(|| {
    Arc::new(ChiaMessageFilter {
        msg_type: Some(ProtocolMessageTypes::NewSignagePoint),
        id: None,
        custom_fn: None,
    })
});
static SIGNED_VALUES_FILTER: Lazy<Arc<ChiaMessageFilter>> = Lazy::new(|| {
    Arc::new(ChiaMessageFilter {
        msg_type: Some(ProtocolMessageTypes::RequestSignedValues),
        id: None,
        custom_fn: None,
    })
});
