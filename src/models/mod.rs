use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Instant;
use blst::min_pk::SecretKey;
use dg_xch_clients::protocols::farmer::NewSignagePoint;
use dg_xch_clients::websocket::farmer::FarmerClient;
use dg_xch_core::blockchain::proof_of_space::ProofOfSpace;
use dg_xch_core::blockchain::sized_bytes::{Bytes32, Bytes48};
use dg_xch_pos::plots::disk_plot::DiskPlot;
use dg_xch_pos::plots::plot_reader::PlotReader;
use tokio::fs::File;
use tokio::sync::Mutex;
use crate::models::config::Config;
use crate::tasks::pool_state_updater::FarmerPoolState;

pub mod config;

type ProofsMap = Arc<Mutex<HashMap<Bytes32, Vec<(String, ProofOfSpace)>>>>;

#[derive(Clone)]
pub struct FarmerSharedState {
    pub(crate) signage_points: Arc<Mutex<HashMap<Bytes32, Vec<NewSignagePoint>>>>,
    pub(crate) plots: Arc<Mutex<HashMap<PathInfo, Arc<Mutex<PlotInfo>>>>>,
    pub(crate) quality_to_identifiers: Arc<Mutex<HashMap<Bytes32, FarmerIdentifier>>>,
    pub(crate) proofs_of_space: ProofsMap,
    pub(crate) cache_time: Arc<Mutex<HashMap<Bytes32, Instant>>>,
    pub(crate) pool_states: Arc<Mutex<HashMap<Bytes32, FarmerPoolState>>>,
    pub(crate) farmer_private_keys: Arc<Vec<SecretKey>>,
    pub(crate) owner_secret_keys: Arc<HashMap<Bytes48, SecretKey>>,
    pub(crate) pool_public_keys: Arc<HashMap<Bytes48, SecretKey>>,
    pub(crate) config: Arc<Config>,
    pub(crate) run: Arc<AtomicBool>,
    pub(crate) full_node_client: Arc<Mutex<Option<FarmerClient>>>,
    pub(crate) farmer_target: Arc<Bytes32>,
    pub(crate) pool_target: Arc<Bytes32>,
}

#[derive(Debug, Clone)]
pub struct PathInfo {
    pub path: PathBuf,
    pub file_name: String,
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
    pub file_size: usize,
    pub time_modified: usize,
}

#[derive(Debug)]
pub struct FarmerIdentifier {
    pub plot_identifier: String,
    pub challenge_hash: Bytes32,
    pub sp_hash: Bytes32,
}