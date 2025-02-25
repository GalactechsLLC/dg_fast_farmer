pub mod druid_garden;
use crate::cli::utils::load_client_id;
use crate::harvesters::druid_garden::DruidGardenHarvester;
use async_trait::async_trait;
use blst::min_pk::SecretKey;
use dg_xch_core::blockchain::sized_bytes::{Bytes32, Bytes48};
use dg_xch_core::protocols::farmer::FarmerSharedState;
use dg_xch_core::protocols::harvester::{
    NewProofOfSpace, NewSignagePointHarvester, RequestSignatures, RespondSignatures,
};
use log::error;
use std::collections::HashMap;
use std::io::Error;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use crate::farmer::config::Config;
use crate::harvesters::Harvesters::DruidGarden;

#[async_trait]
pub trait SignatureHandler {
    async fn handle_signature(&self, new_pos: RespondSignatures) -> Result<(), Error>;
}

#[async_trait]
pub trait ProofHandler {
    async fn handle_proof(&self, new_pos: NewProofOfSpace) -> Result<(), Error>;
}

#[async_trait]
pub trait Harvester<T: 'static, C: 'static> {
    async fn load(
        shared_state: Arc<FarmerSharedState<T>>,
        config: Arc<RwLock<Config<C>>>
    ) -> Result<Arc<HashMap<Bytes32, Arc<Self>>>, Error>;
    async fn new_signage_point<H>(
        &self,
        signage_point: Arc<NewSignagePointHarvester>,
        proof_handle: H,
    ) -> Result<(), Error>
    where
        H: ProofHandler + Sync + Send;
    async fn request_signatures<H>(
        &self,
        request_signatures: RequestSignatures,
        response_handle: H,
    ) -> Result<(), Error>
    where
        H: SignatureHandler + Sync + Send;
    fn uuid(&self) -> Bytes32;
}

pub enum Harvesters<T: Send + Sync + 'static> {
    DruidGarden(DruidGardenHarvester<T>),
}
#[async_trait]
impl<T: Sync + Send + 'static, C: Sync + Send + 'static> Harvester<T, C> for Harvesters<T> {
    async fn load(shared_state: Arc<FarmerSharedState<T>>, config: Arc<RwLock<Config<C>>>) -> Result<Arc<HashMap<Bytes32, Arc<Harvesters<T>>>>, Error> {
        let mut harvesters: HashMap<Bytes32, Arc<Harvesters<T>>> = HashMap::new();
        let mut farmer_public_keys = vec![];
        let mut pool_public_keys = vec![];
        let client_id = load_client_id::<C>(config.clone()).await?;
        let config = config.read().await;
        for farmer_info in &config.farmer_info {
            let f_sk: SecretKey = farmer_info.farmer_secret_key.into();
            farmer_public_keys.push(f_sk.sk_to_pk().to_bytes().into());
            if let Some(pk) = farmer_info.pool_secret_key {
                let p_sk: SecretKey = pk.into();
                pool_public_keys.push(p_sk.sk_to_pk().to_bytes().into());
            }
        }
        let pool_contract_hashes = config
            .pool_info
            .iter()
            .map(|w| w.p2_singleton_puzzle_hash)
            .collect::<Vec<Bytes32>>();
        let mut sum = 0;
        let mut total_size = 0;
        let farming_keys = Arc::new(FarmingKeys {
            farmer_public_keys,
            pool_public_keys,
            pool_contract_hashes,
        });
        if let Some(dg_config) = &config.harvester_configs.druid_garden {
            for dir in &dg_config.plot_directories {
                if let Err(e) = count_plots(Path::new(&dir), &mut sum, &mut total_size).await {
                    error!("Error Counting Plots: {e:?}")
                }
            }
            let harvester = DruidGardenHarvester::new(
                dg_config
                    .plot_directories
                    .iter()
                    .map(|s| Path::new(s).to_path_buf())
                    .collect(),
                farming_keys.clone(),
                shared_state.signal.clone(),
                &config.selected_network,
                client_id,
                shared_state.clone(),
            )
                .await?;
            harvesters.insert(
                <DruidGardenHarvester<T> as Harvester<T, C>>::uuid(&harvester),
                Arc::new(DruidGarden(harvester)),
            );
        }
        Ok(Arc::new(harvesters))
    }

    async fn new_signage_point<H>(&self, signage_point: Arc<NewSignagePointHarvester>, proof_handle: H) -> Result<(), Error>
    where
        H: ProofHandler + Sync + Send
    {
        match self {
            DruidGarden(harvester) => {
                <DruidGardenHarvester<T> as Harvester<T, C>>::new_signage_point::<H>(harvester,signage_point, proof_handle).await
            }
        }
    }

    async fn request_signatures<H>(&self, request_signatures: RequestSignatures, response_handle: H) -> Result<(), Error>
    where
        H: SignatureHandler + Sync + Send
    {
        match self {
            DruidGarden(harvester) => {
                <DruidGardenHarvester<T> as Harvester<T, C>>::request_signatures::<H>(harvester,request_signatures, response_handle).await
            }
        }
    }

    fn uuid(&self) -> Bytes32 {
        match self {
            DruidGarden(harvester) => {
                <DruidGardenHarvester<T> as Harvester<T, C>>::uuid(harvester)
            }
        }
    }
}

pub struct FarmingKeys {
    farmer_public_keys: Vec<Bytes48>,
    pool_public_keys: Vec<Bytes48>,
    pool_contract_hashes: Vec<Bytes32>,
}

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
