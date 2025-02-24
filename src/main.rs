use blst::min_pk::SecretKey;
use clap::Parser;
use dg_fast_farmer::cli::commands::{
    GenerateConfig, cli_mode, generate_config_from_mnemonic, join_pool, tui_mode, update,
    update_pool_info,
};
use dg_fast_farmer::cli::utils::{check_config, get_config_path, get_ssl_root_path, init_logger};
use dg_fast_farmer::cli::{Action, Cli, RunMode};
use dg_fast_farmer::farmer::ExtendedFarmerSharedState;
use dg_fast_farmer::farmer::config::{Config, load_keys};
use dg_fast_farmer::metrics::Metrics;
use dg_xch_clients::api::pool::create_pool_login_url;
use dg_xch_core::blockchain::sized_bytes::Bytes32;
use dg_xch_core::protocols::farmer::{FarmerMetrics, FarmerSharedState};
use dg_xch_core::ssl::create_all_ssl;
use dg_xch_keys::{encode_puzzle_hash, parse_payout_address};
use std::collections::HashMap;
use std::env;
use std::io::{Error, ErrorKind};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use tokio::fs::create_dir_all;
use tokio::sync::RwLock;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let provider = rustls::crypto::ring::default_provider();
    provider.install_default().map_err(|_| {
        Error::new(
            ErrorKind::Other,
            "Failed to Install default Crypto Provider",
        )
    })?;
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
            let mut config = Config::try_from(&config_path)?;
            if let Some(ssl_path) = config.ssl_root_path {
                create_all_ssl(Path::new(&ssl_path), false)?;
                config.ssl_root_path = Some(ssl_path);
            } else {
                let ssl_path = get_ssl_root_path(&config);
                create_all_ssl(&ssl_path, false)?;
                config.ssl_root_path = Some(ssl_path.to_string_lossy().to_string());
            };
            let config = Arc::new(config);
            let (farmer_private_keys, owner_secret_keys, auth_secret_keys, pool_public_keys) =
                load_keys(config.clone()).await;
            let extended_metrics = Arc::new(Metrics::default());
            let farmer_metrics = FarmerMetrics::new(&*extended_metrics.registry.read().await);
            let shared_state = Arc::new(FarmerSharedState {
                farmer_private_keys: Arc::new(farmer_private_keys),
                owner_secret_keys: Arc::new(owner_secret_keys),
                owner_public_keys_to_auth_secret_keys: Arc::new(auth_secret_keys),
                pool_public_keys: Arc::new(pool_public_keys),
                data: Arc::new(ExtendedFarmerSharedState {
                    config: Arc::new(RwLock::new(config.clone())),
                    run: Arc::new(AtomicBool::new(true)),
                    additional_headers: Arc::new(HashMap::new()),
                    extended_metrics,
                    ..Default::default()
                }),
                metrics: Arc::new(RwLock::new(Some(farmer_metrics))),
                ..Default::default()
            });
            match mode.unwrap_or_default() {
                RunMode::Cli => cli_mode(shared_state).await,
                RunMode::Tui => tui_mode(shared_state).await,
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
            let updated_config = update_pool_info(config, launcher_id, None).await?;
            updated_config.save_as_yaml(config_path)?;
            Ok(())
        }
        Action::UpdatePayoutAddress { address } => {
            check_config(&config_path)?;
            init_logger();
            let mut config = Config::try_from(&config_path)?;
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
            init_logger();
            let config = Config::try_from(&config_path).unwrap();
            let updated_config =
                join_pool(config, pool_url, mnemonic_file, launcher_id, fee).await?;
            updated_config.save_as_yaml(config_path)?;
            Ok(())
        }
        Action::GetLoginLink { launcher_id } => {
            check_config(&config_path)?;
            let launcher_id = Bytes32::from_str(&launcher_id)?;
            let config = Config::try_from(&config_path)?;
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
