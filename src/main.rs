use std::collections::HashMap;
use std::env;
use std::io::Error;
use std::path::{Path};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use dg_xch_clients::api::pool::DefaultPoolClient;
use hex::encode;
use log::{info, warn};
use simple_logger::SimpleLogger;
use tokio::join;
use tokio::sync::mpsc::channel;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use dg_xch_clients::protocols::farmer::{NewSignagePoint};
use dg_xch_clients::protocols::harvester::{PoolDifficulty};
use dg_xch_core::blockchain::sized_bytes::{Bytes32, SizedBytes};
use dg_xch_core::consensus::constants::{CONSENSUS_CONSTANTS_MAP, MAINNET};
use dg_xch_serialize::hash_256;
use uuid::Uuid;
use crate::models::config::{Config, load_keys};
use crate::models::{FarmerSharedState};
use crate::tasks::fullnode_client::client_handler;
use crate::tasks::pool_state_updater::pool_updater;
use crate::tasks::signage_point_handler::signage_point_handler;
use dg_xch_keys::decode_puzzle_hash;

pub mod models;
pub mod tasks;

#[tokio::main]
async fn main() -> Result<(), Error> {
    SimpleLogger::new().env().init().unwrap_or_default();

    //Shared Vars
    let config_path = env::var("CONFIG_PATH").unwrap_or_else(|_| String::from("./farmer.yaml"));
    let path = Path::new(&config_path);
    if !path.exists() {
        warn!("No Config Found at {:?}, will use default", config_path);
    }
    let config_arc = Arc::new(Config::try_from(path).unwrap());
    let constants = CONSENSUS_CONSTANTS_MAP
        .get(&config_arc.selected_network)
        .unwrap_or(&MAINNET); //Defaults to mainnet
    info!(
        "Selected Network: {}, AggSig: {}",
        &config_arc.selected_network,
        &encode(&constants.agg_sig_me_additional_data)
    );
    let pool_client = Arc::new(DefaultPoolClient::new());
    let (farmer_private_keys, owner_secret_keys, pool_public_keys) = load_keys(config_arc.clone()).await;
    let farmer_target_encoded = &config_arc.payout_address;
    let farmer_target = decode_puzzle_hash(farmer_target_encoded)?;
    let pool_target = decode_puzzle_hash(farmer_target_encoded)?;
    let shared_state = Arc::new(FarmerSharedState{
        signage_points: Arc::new(Default::default()),
        plots: Arc::new(Default::default()),
        quality_to_identifiers: Arc::new(Mutex::new(HashMap::new())),
        proofs_of_space: Arc::new(Default::default()),
        cache_time: Arc::new(Default::default()),
        pool_states: Arc::new(Default::default()),
        farmer_private_keys: Arc::new(farmer_private_keys),
        owner_secret_keys: Arc::new(owner_secret_keys),
        pool_public_keys: Arc::new(pool_public_keys),
        config: config_arc.clone(),
        run: Arc::new(AtomicBool::new(true)),
        full_node_client: Arc::new(Default::default()),
        farmer_target: Arc::new(farmer_target),
        pool_target: Arc::new(pool_target),
    });


    //Pool Updater vars
    let pool_state = shared_state.clone();
    let pool_state_handle: JoinHandle<()> = tokio::spawn(async move {
        pool_updater(pool_state).await
    });

    //Client Vars
    let client_state = shared_state.clone();
    let(signage_sender, signage_receiver) = channel::<(NewSignagePoint, Vec<PoolDifficulty>)>(32);
    let client_handle: JoinHandle<Result<(), Error>> = tokio::spawn(async move {
        client_handler(
            client_state,
            signage_sender,
        ).await;
        Ok(())
    });

    //Signage Handler Vars
    let signage_point_pool_client = pool_client.clone();
    let signage_point_harvester_id = Arc::new(Bytes32::new(&hash_256(Uuid::new_v4().as_ref())));
    let signage_state = shared_state.clone();
    let signage_point_handle: JoinHandle<Result<(), Error>> = tokio::spawn(async move {
        signage_point_handler(
            signage_receiver,
            signage_state,
            signage_point_pool_client,
            signage_point_harvester_id,
        ).await
    });

    let _ = join!(pool_state_handle, client_handle, signage_point_handle);
    Ok(())
}