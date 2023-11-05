pub mod druid_garden;

use crate::farmer::config::Config;
use crate::harvesters::druid_garden::DruidGardenHarvester;
use async_trait::async_trait;
use blst::min_pk::SecretKey;
use dg_xch_clients::protocols::harvester::{
    NewProofOfSpace, NewSignagePointHarvester, RequestSignatures, RespondSignatures,
};
use dg_xch_core::blockchain::sized_bytes::Bytes32;
use std::collections::HashMap;
use std::io::Error;
use std::path::Path;
use std::sync::atomic::AtomicBool;
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
        proof_handle: Arc<T>,
    ) -> Result<(), Error>
    where
        T: ProofHandler + Sync + Send;
    async fn request_signatures<T>(
        &self,
        request_signatures: RequestSignatures,
        response_handle: Arc<T>,
    ) -> Result<(), Error>
    where
        T: SignatureHandler + Sync + Send;
    fn uuid(&self) -> Uuid;
}

pub enum Harvesters {
    DruidGarden(DruidGardenHarvester),
}

pub async fn load_harvesters(
    config: Arc<Config>,
    shutdown_signal: Arc<AtomicBool>,
) -> Result<Arc<HashMap<Uuid, Arc<Harvesters>>>, Error> {
    let mut harvesters: HashMap<Uuid, Arc<Harvesters>> = HashMap::new();
    let mut farmer_public_keys = vec![];
    let mut pool_public_keys = vec![];
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
    if let Some(bb_config) = &config.harvester_configs.bladebit {
        let harvester = DruidGardenHarvester::new(
            bb_config
                .plot_directories
                .iter()
                .map(|s| Path::new(s).to_path_buf())
                .collect(),
            farmer_public_keys,
            pool_public_keys,
            pool_contract_hashes,
            shutdown_signal,
            &config.selected_network,
        )
        .await?;
        harvesters.insert(
            harvester.uuid(),
            Arc::new(Harvesters::DruidGarden(harvester)),
        );
    }
    Ok(Arc::new(harvesters))
}
