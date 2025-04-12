use crate::cli::commands::{
    GenerateConfig, cli_mode, generate_config_from_mnemonic, join_pool, tui_mode, update,
    update_pool_info,
};
use crate::cli::utils::{check_config, get_config_path, get_ssl_root_path, init_logger};
use crate::cli::{Action, Cli};
use crate::farmer::config::{Config, load_keys};
use crate::farmer::protocols::harvester::new_proof_of_space::NewProofOfSpaceHandle;
use crate::farmer::protocols::harvester::respond_signatures::RespondSignaturesHandler;
use crate::harvesters::druid_garden::DruidGardenHarvester;
use crate::harvesters::{Harvester, ProofHandler, SignatureHandler};
use crate::metrics::get_metrics;
use blst::min_pk::SecretKey;
use clap::Parser;
use dg_xch_clients::api::pool::{DefaultPoolClient, create_pool_login_url};
use dg_xch_core::blockchain::sized_bytes::Bytes32;
use dg_xch_core::protocols::farmer::FarmerSharedState;
use dg_xch_core::ssl::create_all_ssl;
use dg_xch_keys::{encode_puzzle_hash, parse_payout_address};
use dg_xch_serialize::ChiaProtocolVersion;
use once_cell::sync::Lazy;
use portfu::prelude::http::header::USER_AGENT;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::env;
use std::io::{Error, ErrorKind};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use tokio::fs::create_dir_all;
use tokio::sync::RwLock;

const PROTOCOL_VERSION: ChiaProtocolVersion = ChiaProtocolVersion::Chia0_0_36;

fn _version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
fn _pkg_name() -> &'static str {
    env!("CARGO_PKG_NAME")
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
    println!("{}", header_version());
}

pub static HEADERS: Lazy<HashMap<String, String>> = Lazy::new(|| {
    let mut headers = HashMap::new();
    headers.insert(
        String::from("X-fast-farmer-version"),
        _version().to_string(),
    );
    headers.insert(USER_AGENT.to_string(), header_version());
    headers.insert(String::from("X-dg-xch-pos-version"), dg_xch_pos::version());
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
pub mod metrics;
pub mod tasks;

pub enum RunMode {
    Cli,
    Tui,
}

pub struct RunArgs<T> {
    pub mode: RunMode,
    pub shared_state: Arc<FarmerSharedState<T>>,
}

pub type SignaturesHandler =
    RespondSignaturesHandler<DefaultPoolClient, (), DruidGardenHarvester<()>, ()>;
pub type NewProofHandler =
    NewProofOfSpaceHandle<DefaultPoolClient, SignaturesHandler, (), DruidGardenHarvester<()>, ()>;

pub async fn run(args: RunArgs<()>, config: Config<()>) -> Result<(), Error> {
    let config = Arc::new(RwLock::new(config));
    match args.mode {
        RunMode::Cli => {
            cli_mode::<(), DruidGardenHarvester<()>, (), NewProofHandler, SignaturesHandler>(
                args.shared_state,
                config,
            )
            .await
        }
        RunMode::Tui => {
            tui_mode::<(), DruidGardenHarvester<()>, (), NewProofHandler, SignaturesHandler>(
                args.shared_state,
                config,
            )
            .await
        }
    }
}

pub async fn run_with_custom_harvester<T, H, C, O, S>(
    args: RunArgs<T>,
    config: Arc<RwLock<Config<C>>>,
) -> Result<(), Error>
where
    T: Sync + Send + 'static,
    H: Harvester<T, H, C> + Sync + Send + 'static,
    C: Sync + Send + Clone + 'static,
    O: ProofHandler<T, H, C> + Sync + Send + 'static,
    S: SignatureHandler<T, H, C> + Sync + Send + 'static,
{
    match args.mode {
        RunMode::Cli => cli_mode::<T, H, C, O, S>(args.shared_state, config).await,
        RunMode::Tui => tui_mode::<T, H, C, O, S>(args.shared_state, config).await,
    }
}

pub async fn cli<T, H, C, O, S>(additional_state: Arc<T>) -> Result<(), Error>
where
    T: Default + Sync + Send + 'static,
    H: Harvester<T, H, C> + Sync + Send + 'static,
    C: for<'a> Deserialize<'a> + Sync + Send + Clone + Serialize + 'static,
    O: ProofHandler<T, H, C> + Sync + Send + 'static,
    S: SignatureHandler<T, H, C> + Sync + Send + 'static,
{
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
            let mut config: Config<C> = Config::<C>::try_from(config_path.as_path())?;
            if let Some(ssl_path) = config.ssl_root_path {
                create_all_ssl(Path::new(&ssl_path), false)?;
                config.ssl_root_path = Some(ssl_path);
            } else {
                let ssl_path = get_ssl_root_path(&config);
                create_all_ssl(&ssl_path, false)?;
                config.ssl_root_path = Some(ssl_path.to_string_lossy().to_string());
            };
            let (farmer_private_keys, owner_secret_keys, auth_secret_keys, pool_public_keys) =
                load_keys(&config).await;
            let shared_state = Arc::new(FarmerSharedState {
                farmer_private_keys: Arc::new(farmer_private_keys),
                owner_secret_keys: Arc::new(owner_secret_keys),
                owner_public_keys_to_auth_secret_keys: Arc::new(auth_secret_keys),
                pool_public_keys: Arc::new(pool_public_keys),
                data: additional_state,
                metrics: Arc::new(RwLock::new(Some(get_metrics()))),
                signal: Arc::new(AtomicBool::new(true)),
                ..Default::default()
            });
            let config = Arc::new(RwLock::new(config));
            match mode.unwrap_or_default() {
                cli::RunMode::Cli => cli_mode::<T, H, C, O, S>(shared_state, config).await,
                cli::RunMode::Tui => tui_mode::<T, H, C, O, S>(shared_state, config).await,
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
            let _logger = init_logger();
            generate_config_from_mnemonic(
                GenerateConfig {
                    output_path: Some(config_path),
                    mnemonic_file,
                    mnemonic_string: None,
                    fullnode_ws_host,
                    fullnode_ws_port,
                    fullnode_rpc_host,
                    fullnode_rpc_port,
                    fullnode_ssl,
                    network,
                    launcher_id: launcher_id
                        .map(|l| Bytes32::from_str(&l).expect("Invalid Launcher ID Provided")),
                    payout_address,
                    plot_directories,
                    additional_headers: None,
                },
                true,
            )
            .await?;
            Ok(())
        }
        Action::Update {} => {
            check_config(&config_path)?;
            let _logger = init_logger();
            let config = Config::<C>::try_from(&config_path)?;
            let updated_config = update::<C>(config).await?;
            updated_config.save_as_yaml(config_path)?;
            Ok(())
        }
        Action::UpdatePoolInfo { launcher_id } => {
            check_config(&config_path)?;
            let _logger = init_logger();
            let config = Config::<C>::try_from(&config_path)?;
            let updated_config = update_pool_info::<C>(config, launcher_id, None).await?;
            updated_config.save_as_yaml(config_path)?;
            Ok(())
        }
        Action::UpdatePayoutAddress { address } => {
            check_config(&config_path)?;
            let _logger = init_logger();
            let mut config = Config::<C>::try_from(&config_path)?;
            let payout_address = parse_payout_address(&address)?;
            let xch_address = encode_puzzle_hash(&Bytes32::from_str(&payout_address)?, "xch")?;
            for pool_info in &mut config.pool_info {
                pool_info.payout_instructions.clone_from(&xch_address);
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
            let _logger = init_logger();
            let config = Config::<C>::try_from(&config_path).unwrap();
            let updated_config =
                join_pool::<C>(config, pool_url, mnemonic_file, launcher_id, fee).await?;
            updated_config.save_as_yaml(config_path)?;
            Ok(())
        }
        Action::GetLoginLink { launcher_id } => {
            check_config(&config_path)?;
            let launcher_id = Bytes32::from_str(&launcher_id)?;
            let config = Config::<C>::try_from(&config_path)?;
            let auth_secret_key = config
                .farmer_info
                .iter()
                .find_map(|v| {
                    if v.launcher_id == Some(launcher_id) {
                        Some(v.auth_secret_key)
                    } else {
                        None
                    }
                })
                .ok_or_else(|| {
                    Error::new(
                        ErrorKind::NotFound,
                        format!(
                            "Failed to find Farmer Info in config for launcher id {launcher_id}"
                        ),
                    )
                })?
                .ok_or_else(|| {
                    Error::new(
                        ErrorKind::NotFound,
                        format!("No Auth key for launcher id {launcher_id}"),
                    )
                })?;
            let pool_url = config
                .pool_info
                .iter()
                .find_map(|v| {
                    if v.launcher_id == launcher_id {
                        Some(v.pool_url.clone())
                    } else {
                        None
                    }
                })
                .ok_or_else(|| {
                    Error::new(
                        ErrorKind::NotFound,
                        format!("Failed to find Pool Url in config for launcher id {launcher_id}"),
                    )
                })?;
            let auth_key: SecretKey = auth_secret_key.into();
            let link = create_pool_login_url(&pool_url, &[(auth_key, launcher_id)]).await?;
            println!("{link}");
            Ok(())
        }
    }
}
