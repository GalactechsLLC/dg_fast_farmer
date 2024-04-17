use crate::cli::commands::{
    cli_mode, generate_config_from_mnemonic, join_pool, tui_mode, update, update_pool_info,
    GenerateConfig,
};
use crate::cli::utils::{check_config, get_config_path, init_logger};
use crate::cli::{Action, Cli, RunMode};
use crate::farmer::config::Config;
use clap::Parser;
use dg_xch_core::blockchain::sized_bytes::Bytes32;
use dg_xch_keys::{encode_puzzle_hash, parse_payout_address};
use dg_xch_serialize::ChiaProtocolVersion;
use once_cell::sync::Lazy;
use reqwest::header::USER_AGENT;
use std::collections::HashMap;
use std::env;
use std::io::Error;
use std::path::PathBuf;
use tokio::fs::create_dir_all;

const PROTOCOL_VERSION: ChiaProtocolVersion = ChiaProtocolVersion::Chia0_0_36;

fn _version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
fn _pkg_name() -> &'static str {
    env!("CARGO_PKG_NAME")
}
fn gh_version() -> &'static str {
    "3.0"
}
fn chia_version() -> &'static str {
    "2.2.1"
}
pub fn version() -> String {
    format!("{}: {}", _pkg_name(), _version())
}
pub fn header_version() -> String {
    format!("{}={}", _pkg_name(), _version())
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
    headers.insert(USER_AGENT.to_string(), header_version());
    headers.insert(String::from("X-dg-xch-pos-version"), dg_xch_pos::version());
    headers.insert(String::from("X-gh-version"), gh_version().to_string());
    headers.insert(String::from("X-chia-version"), chia_version().to_string());
    headers.insert(
        String::from("X-chia-protocol-version"),
        PROTOCOL_VERSION.to_string(),
    );
    headers
});

pub mod cli;
pub mod farmer;
pub mod gui;
pub mod harvesters;
mod metrics;
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
        Action::Run { mode } => {
            check_config(&config_path)?;
            match mode.unwrap_or_default() {
                RunMode::Cli => cli_mode(config_path.as_path()).await,
                RunMode::Tui => tui_mode(config_path.as_path()).await,
            }
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
            init_logger();
            generate_config_from_mnemonic(GenerateConfig {
                output_path: Some(config_path),
                mnemonic_file,
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
        Action::Update {} => {
            check_config(&config_path)?;
            init_logger();
            let config = Config::try_from(&config_path)?;
            let updated_config = update(config).await?;
            updated_config.save_as_yaml(config_path)?;
            Ok(())
        }
        Action::UpdatePoolInfo { launcher_id } => {
            check_config(&config_path)?;
            init_logger();
            let config = Config::try_from(&config_path)?;
            let updated_config = update_pool_info(config, launcher_id).await?;
            updated_config.save_as_yaml(config_path)?;
            Ok(())
        }
        Action::UpdatePayoutAddress { address } => {
            check_config(&config_path)?;
            init_logger();
            let mut config = Config::try_from(&config_path)?;
            let payout_address = parse_payout_address(&address)?;
            let xch_address = encode_puzzle_hash(&Bytes32::from(payout_address), "xch")?;
            for pool_info in &mut config.pool_info {
                pool_info.payout_instructions = xch_address.clone();
            }
            config.payout_address = xch_address;
            config.save_as_yaml(config_path)?;
            Ok(())
        }
        Action::JoinPool {
            pool_url,
            mnemonic_file,
            launcher_id,
            fee,
        } => {
            check_config(&config_path)?;
            init_logger();
            let config = Config::try_from(&config_path).unwrap();
            let updated_config =
                join_pool(config, pool_url, mnemonic_file, launcher_id, fee).await?;
            updated_config.save_as_yaml(config_path)?;
            Ok(())
        }
    }
}
