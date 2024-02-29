use crate::cli::{
    generate_config_from_mnemonic, get_config_path, join_pool, load_mnemonic_from_file,
    prompt_for_mnemonic, update_pool_info, Action, Cli, GenerateConfig,
};
use crate::farmer::config::{load_keys, Config};
use crate::farmer::{ExtendedFarmerSharedState, Farmer};
use crate::tasks::pool_state_updater::pool_updater;
use clap::Parser;
use dg_xch_clients::api::pool::DefaultPoolClient;
use dg_xch_core::blockchain::sized_bytes::Bytes32;
use dg_xch_core::consensus::constants::{CONSENSUS_CONSTANTS_MAP, MAINNET};
use dg_xch_core::protocols::farmer::FarmerSharedState;
use dg_xch_core::utils::await_termination;
use hex::encode;
use log::{error, info, LevelFilter};
use once_cell::sync::Lazy;
use reqwest::header::USER_AGENT;
use simple_logger::SimpleLogger;
use std::collections::HashMap;
use std::env;
use std::io::Error;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::fs::create_dir_all;
use tokio::join;
use tokio::task::JoinHandle;

fn _version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
fn _pkg_name() -> &'static str {
    env!("CARGO_PKG_NAME")
}

pub fn version() -> String {
    format!("{}: {}", _pkg_name(), _version())
}

#[test]
fn version_test() {
    println!("{}", version());
}

pub static HEADERS: Lazy<HashMap<String, String>> = Lazy::new(|| {
    let mut headers = HashMap::new();
    headers.insert(
        String::from("X-fast-farmer-version"),
        _version().to_string(),
    );
    headers.insert(USER_AGENT.to_string(), version());
    headers.insert(String::from("X-dg-xch-pos-version"), dg_xch_pos::version());
    headers
});

pub mod cli;
pub mod farmer;
pub mod gui;
pub mod harvesters;
pub mod tasks;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let cli = Cli::parse();
    let config_path = if let Some(s) = &cli.config {
        PathBuf::from(s)
    } else if let Ok(s) = env::var("CONFIG_PATH") {
        PathBuf::from(s)
    } else {
        let config_path = get_config_path();
        if let Some(parent) = config_path.parent() {
            create_dir_all(parent).await?;
        }
        config_path
    };
    let action = cli.action.unwrap_or_default();
    match action {
        Action::Gui {} => {
            if !config_path.exists() {
                eprintln!(
                    "Failed to find config at {:?}, please run init",
                    config_path
                );
                return Ok(());
            }
            let config = Config::try_from(&config_path).unwrap_or_default();
            let config_arc = Arc::new(config);
            gui::bootstrap(config_arc).await?;
            Ok(())
        }
        Action::Run {} => {
            if !config_path.exists() {
                eprintln!(
                    "Failed to find config at {:?}, please run init",
                    config_path
                );
                return Ok(());
            }
            SimpleLogger::new()
                .with_colors(true)
                .with_level(LevelFilter::Info)
                .env()
                .init()
                .unwrap_or_default();
            let config = Config::try_from(&config_path).unwrap();
            let config_arc = Arc::new(config);
            let constants = CONSENSUS_CONSTANTS_MAP
                .get(&config_arc.selected_network)
                .unwrap_or(&MAINNET);
            info!(
                "Selected Network: {}, AggSig: {}",
                &config_arc.selected_network,
                &encode(&constants.agg_sig_me_additional_data)
            );
            let (farmer_private_keys, owner_secret_keys, auth_secret_keys, pool_public_keys) =
                load_keys(config_arc.clone()).await;
            let shared_state = Arc::new(FarmerSharedState {
                farmer_private_keys: Arc::new(farmer_private_keys),
                owner_secret_keys: Arc::new(owner_secret_keys),
                auth_secret_keys: Arc::new(auth_secret_keys),
                pool_public_keys: Arc::new(pool_public_keys),
                data: Arc::new(ExtendedFarmerSharedState {
                    config: config_arc.clone(),
                    run: Arc::new(AtomicBool::new(true)),
                    ..Default::default()
                }),
                ..Default::default()
            });

            info!("Using Additional Headers: {:?}", &*HEADERS);
            //Pool Updater vars
            let pool_state = shared_state.clone();
            let pool_state_handle: JoinHandle<()> =
                tokio::spawn(async move { pool_updater(pool_state).await });

            //Signal Handler to Shutdown the Async processes
            let signal_run = shared_state.data.run.clone();
            let signal_handle = tokio::spawn(async move {
                let _ = await_termination().await;
                signal_run.store(false, Ordering::Relaxed);
            });

            let pool_client = Arc::new(DefaultPoolClient::new());
            let farmer = Farmer::new(shared_state, pool_client).await?;

            //Client Vars
            let client_handle: JoinHandle<Result<(), Error>> = tokio::spawn(async move {
                farmer.run().await;
                Ok(())
            });
            let _ = join!(pool_state_handle, client_handle, signal_handle);
            Ok(())
        }
        Action::Init {
            fullnode_ws_host,
            fullnode_ws_port,
            fullnode_rpc_host,
            fullnode_rpc_port,
            fullnode_ssl,
            network,
            payout_address,
            plot_directories,
            mnemonic_file,
            launcher_id,
        } => {
            SimpleLogger::new()
                .with_colors(true)
                .with_level(LevelFilter::Info)
                .env()
                .init()
                .unwrap_or_default();
            let mnemonic = if let Some(mnemonic_file) = mnemonic_file {
                load_mnemonic_from_file(mnemonic_file)?
            } else {
                prompt_for_mnemonic()?
            };
            generate_config_from_mnemonic(GenerateConfig {
                output_path: Some(config_path),
                mnemonic,
                fullnode_ws_host,
                fullnode_ws_port,
                fullnode_rpc_host,
                fullnode_rpc_port,
                fullnode_ssl,
                network,
                launcher_id: launcher_id.map(Bytes32::from),
                payout_address,
                plot_directories,
                additional_headers: None,
            })
            .await?;
            Ok(())
        }
        Action::UpdatePoolInfo {} => {
            SimpleLogger::new()
                .with_colors(true)
                .with_level(LevelFilter::Info)
                .env()
                .init()
                .unwrap_or_default();
            if !config_path.exists() {
                error!(
                    "Failed to find config at {:?}, please run init",
                    config_path
                );
                return Ok(());
            }
            let config = Config::try_from(&config_path).unwrap_or_default();
            let updated_config = update_pool_info(config).await?;
            updated_config.save_as_yaml(config_path)?;
            Ok(())
        }
        Action::JoinPool {
            pool_url,
            mnemonic,
            launcher_id,
            fee,
        } => {
            if !config_path.exists() {
                eprintln!(
                    "Failed to find config at {:?}, please run init",
                    config_path
                );
                return Ok(());
            }
            SimpleLogger::new()
                .with_colors(true)
                .with_level(LevelFilter::Info)
                .env()
                .init()
                .unwrap_or_default();
            let config = Config::try_from(&config_path).unwrap_or_default();
            let updated_config = join_pool(config, pool_url, mnemonic, launcher_id, fee).await?;
            updated_config.save_as_yaml(config_path)?;

            Ok(())
        }
    }
}
