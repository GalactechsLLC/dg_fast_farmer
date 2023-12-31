use crate::cli::{generate_config_from_mnemonic, Action, Cli, GenerateConfig};
use crate::farmer::config::{load_keys, Config};
use crate::farmer::{Farmer, FarmerSharedState};
use crate::tasks::pool_state_updater::pool_updater;
use clap::Parser;
use dg_xch_clients::api::pool::DefaultPoolClient;
use dg_xch_core::consensus::constants::{CONSENSUS_CONSTANTS_MAP, MAINNET};
use dg_xch_keys::decode_puzzle_hash;
use hex::encode;
use home::home_dir;
use log::{info, LevelFilter};
use once_cell::sync::Lazy;
use reqwest::header::USER_AGENT;
use simple_logger::SimpleLogger;
use std::collections::HashMap;
use std::env;
use std::io::Error;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;
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

fn get_root_path() -> PathBuf {
    let prefix = match home_dir() {
        Some(path) => path,
        None => Path::new("/").to_path_buf(),
    };
    prefix.as_path().join(Path::new(".config/fast_farmer/"))
}

fn get_config_path() -> PathBuf {
    get_root_path()
        .as_path()
        .join(Path::new("fast_farmer.yaml"))
}

fn get_ssl_root_path(shared_state: &FarmerSharedState) -> PathBuf {
    if let Some(ssl_root_path) = &shared_state.config.ssl_root_path {
        PathBuf::from(ssl_root_path)
    } else {
        get_root_path().as_path().join(Path::new("ssl/"))
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let cli = Cli::parse();
    let config_path = if let Some(s) = &cli.config {
        PathBuf::from(s)
    } else {
        create_dir_all(get_root_path()).await?;
        get_config_path()
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
            let config = Config::try_from(&config_path).unwrap_or_default();
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
            let farmer_target_encoded = &config_arc.payout_address;
            let farmer_target = decode_puzzle_hash(farmer_target_encoded)?;
            let pool_target = decode_puzzle_hash(farmer_target_encoded)?;
            let shared_state = Arc::new(FarmerSharedState {
                farmer_private_keys: Arc::new(farmer_private_keys),
                owner_secret_keys: Arc::new(owner_secret_keys),
                auth_secret_keys: Arc::new(auth_secret_keys),
                pool_public_keys: Arc::new(pool_public_keys),
                config: config_arc.clone(),
                run: Arc::new(AtomicBool::new(true)),
                farmer_target: Arc::new(farmer_target),
                pool_target: Arc::new(pool_target),
                ..Default::default()
            });

            info!("Using Additional Headers: {:?}", &*HEADERS);
            //Pool Updater vars
            let pool_state = shared_state.clone();
            let pool_state_handle: JoinHandle<()> =
                tokio::spawn(async move { pool_updater(pool_state).await });

            let pool_client = Arc::new(DefaultPoolClient::new());
            let farmer = Farmer::new(shared_state, pool_client).await?;

            //Client Vars
            let client_handle: JoinHandle<Result<(), Error>> = tokio::spawn(async move {
                farmer.run().await;
                Ok(())
            });
            let _ = join!(pool_state_handle, client_handle);
            Ok(())
        }
        Action::Init {
            mnemonic,
            fullnode_ws_host,
            fullnode_ws_port,
            fullnode_rpc_host,
            fullnode_rpc_port,
            fullnode_ssl,
            network,
            payout_address,
            plot_directories,
        } => {
            SimpleLogger::new()
                .with_colors(true)
                .with_level(LevelFilter::Info)
                .env()
                .init()
                .unwrap_or_default();
            generate_config_from_mnemonic(GenerateConfig {
                output_path: Some(config_path),
                mnemonic: &mnemonic,
                fullnode_ws_host,
                fullnode_ws_port,
                fullnode_rpc_host,
                fullnode_rpc_port,
                fullnode_ssl,
                network,
                payout_address,
                plot_directories,
                additional_headers: None,
            })
            .await?;
            Ok(())
        }
    }
}
