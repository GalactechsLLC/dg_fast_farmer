pub mod druid_garden;

use crate::farmer::FarmerSharedState;
use crate::harvesters::druid_garden::DruidGardenHarvester;
use async_trait::async_trait;
use blst::min_pk::SecretKey;
use dg_xch_clients::protocols::harvester::{
    NewProofOfSpace, NewSignagePointHarvester, RequestSignatures, RespondSignatures,
};
use dg_xch_core::blockchain::sized_bytes::Bytes32;
use log::error;
use std::collections::HashMap;
use std::io::Error;
use std::path::Path;
use std::sync::Arc;
use uuid::Uuid;

#[async_trait]
pub trait SignatureHandler {
    async fn handle_signature(&self, new_pos: RespondSignatures) -> Result<(), Error>;
}

#[async_trait]
pub trait ProofHandler {
    async fn handle_proof(&self, new_pos: NewProofOfSpace) -> Result<(), Error>;
}

#[async_trait]
pub trait Harvester {
    async fn new_signage_point<T>(
        &self,
        signage_point: Arc<NewSignagePointHarvester>,
        proof_handle: T,
    ) -> Result<(), Error>
    where
        T: ProofHandler + Sync + Send;
    async fn request_signatures<T>(
        &self,
        request_signatures: RequestSignatures,
        response_handle: T,
    ) -> Result<(), Error>
    where
        T: SignatureHandler + Sync + Send;
    fn uuid(&self) -> Uuid;
}

pub enum Harvesters {
    DruidGarden(DruidGardenHarvester),
}

pub async fn load_harvesters(
    shared_state: Arc<FarmerSharedState>,
) -> Result<Arc<HashMap<Uuid, Arc<Harvesters>>>, Error> {
    let mut harvesters: HashMap<Uuid, Arc<Harvesters>> = HashMap::new();
    let mut farmer_public_keys = vec![];
    let mut pool_public_keys = vec![];
    for farmer_info in &shared_state.config.farmer_info {
        let f_sk: SecretKey = farmer_info.farmer_secret_key.into();
        farmer_public_keys.push(f_sk.sk_to_pk().to_bytes().into());
        if let Some(pk) = farmer_info.pool_secret_key {
            let p_sk: SecretKey = pk.into();
            pool_public_keys.push(p_sk.sk_to_pk().to_bytes().into());
        }
    }
    shared_state.gui_stats.lock().await.keys = farmer_public_keys.clone();
    let pool_contract_hashes = shared_state
        .config
        .pool_info
        .iter()
        .map(|w| w.p2_singleton_puzzle_hash)
        .collect::<Vec<Bytes32>>();
    let mut sum = 0;
    let mut total_size = 0;
    if let Some(bb_config) = &shared_state.config.harvester_configs.bladebit {
        for dir in &bb_config.plot_directories {
            if let Err(e) = count_plots(Path::new(&dir), &mut sum, &mut total_size).await {
                error!("Error Counting Plots: {e:?}")
            }
        }
        let harvester = DruidGardenHarvester::new(
            bb_config
                .plot_directories
                .iter()
                .map(|s| Path::new(s).to_path_buf())
                .collect(),
            farmer_public_keys,
            pool_public_keys,
            pool_contract_hashes,
            shared_state.run.clone(),
            &shared_state.config.selected_network,
        )
        .await?;
        harvesters.insert(
            harvester.uuid(),
            Arc::new(Harvesters::DruidGarden(harvester)),
        );
    }
    shared_state.gui_stats.lock().await.total_plot_count = sum;
    shared_state.gui_stats.lock().await.total_plot_space = total_size;
    Ok(Arc::new(harvesters))
}

pub static EXPECTED_UNCOMPRESSED_MIN: u64 = 0;

async fn count_plots(
    path: &Path,
    count_total: &mut u64,
    size_total: &mut u64,
) -> Result<(), Error> {
    if !path.is_dir() {
        return Ok(());
    }
    let mut dir = tokio::fs::read_dir(path).await?;
    while let Ok(Some(e)) = dir.next_entry().await {
        if e.file_name().to_string_lossy().ends_with(".plot") {
            let file_size = e.metadata().await?.len();
            *size_total += file_size;
            *count_total += 1;
        }
    }
    Ok(())
}
