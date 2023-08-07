use std::collections::HashMap;
use std::env;
use std::io::Error;
use std::path::{Path};
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use hex::encode;
use log::{info, warn};
use simple_logger::SimpleLogger;
use tokio::join;
use tokio::sync::mpsc::channel;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use dg_xch_clients::protocols::farmer::{NewSignagePoint};
use dg_xch_clients::protocols::harvester::{NewProofOfSpace, PoolDifficulty, RequestSignatures};
use dg_xch_core::consensus::constants::{CONSENSUS_CONSTANTS_MAP, MAINNET};
use crate::models::config::Config;
use crate::models::PlotInfo;
use crate::tasks::fullnode_client::client_handler;
use crate::tasks::new_proof_of_space::new_proof_of_space;
use crate::tasks::pool_update::pool_updater;
use crate::tasks::signage_point_handler::signage_point_handler;

pub mod models;
pub mod tasks;

#[tokio::main]
async fn main() -> Result<(), Error> {
    SimpleLogger::new().env().init().unwrap_or_default();
    let config_path = env::var("CONFIG_PATH").unwrap_or_else(|_| String::from("./farmer.yaml"));
    let path = Path::new(&config_path);
    if !path.exists() {
        warn!("No Config Found at {:?}, will use default", config_path);
    }
    let config_arc = Arc::new(Config::try_from(path).unwrap_or_default());
    let constants = CONSENSUS_CONSTANTS_MAP
        .get(&config_arc.selected_network)
        .unwrap_or(&MAINNET); //Defaults to mainnet
    info!(
        "Selected Network: {}, AggSig: {}",
        &config_arc.selected_network,
        &encode(constants.agg_sig_me_additional_data)
    );
    let running = AtomicBool::new(true);
    let plots: Arc<Mutex<HashMap<String, Arc<PlotInfo>>>> = Arc::new(Default::default());

    let pool_update_config_arc = config_arc.clone();
    let pool_state_handle: JoinHandle<()> = tokio::spawn(async move {
        pool_updater(&running, pool_update_config_arc).await
    });


    let quality_to_identifiers = Arc::new(Mutex::new(HashMap::new()));
    let client_handle_config_arc = config_arc.clone();
    let quality_to_identifiers_arc = quality_to_identifiers.clone();
    let(signage_sender, signage_reciever) = channel::<(NewSignagePoint, Vec<PoolDifficulty>)>(32);
    let(signature_sender, signature_reciever) = channel::<RequestSignatures>(32);
    let client_handle: JoinHandle<Result<(), Error>> = tokio::spawn(async move {
        client_handler(&running, client_handle_config_arc, signage_sender, signature_sender.clone(), quality_to_identifiers_arc.clone()).await;
        Ok(())
    });

    let signage_point_config_arc = config_arc.clone();
    let signage_point_plots = plots.clone();
    let(new_proof_of_space_sender, new_proof_of_space_reciever) = channel::<NewProofOfSpace>(32);
    let signage_point_handle: JoinHandle<Result<(), Error>> = tokio::spawn(async move {
        signage_point_handler(signage_reciever, new_proof_of_space_sender, signage_point_config_arc, signage_point_plots).await
    });

    let new_proof_of_space_config_arc = config_arc.clone();
    let new_proof_of_space_handle: JoinHandle<Result<(), Error>> = tokio::spawn(async move {
        new_proof_of_space(new_proof_of_space_reciever, signature_sender, quality_to_identifiers, new_proof_of_space_config_arc).await
    });


    let _ = join!(pool_state_handle, client_handle);
    Ok(())
}