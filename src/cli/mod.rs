use crate::farmer::config::{BladebitHarvesterConfig, Config, FarmingInfo, PoolWalletConfig};
use clap::{Parser, Subcommand};
use dg_xch_cli::wallets::plotnft_utils::{get_plotnft_by_launcher_id, scrounge_for_plotnfts};
use dg_xch_clients::rpc::full_node::FullnodeClient;
use dg_xch_core::blockchain::sized_bytes::Bytes48;
use dg_xch_core::consensus::constants::CONSENSUS_CONSTANTS_MAP;
use dg_xch_keys::{
    key_from_mnemonic, master_sk_to_farmer_sk, master_sk_to_pool_sk,
    master_sk_to_pooling_authentication_sk, master_sk_to_singleton_owner_sk,
    master_sk_to_wallet_sk, master_sk_to_wallet_sk_unhardened,
};
use dg_xch_puzzles::clvm_puzzles::launcher_id_to_p2_puzzle_hash;
use dg_xch_puzzles::p2_delegated_puzzle_or_hidden_puzzle::puzzle_hash_for_pk;
use dialoguer::Confirm;
use log::info;
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub action: Option<Action>,
    #[arg(short, long, value_name = "FILE")]
    pub config: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum Action {
    Gui {},
    Run {},
    Init {
        #[arg(short, long)]
        mnemonic: String,
        #[arg(short = 'f', long)]
        fullnode_ws_host: Option<String>,
        #[arg(short = 'p', long)]
        fullnode_ws_port: Option<u16>,
        #[arg(short = 'r', long)]
        fullnode_rpc_host: Option<String>,
        #[arg(short = 'o', long)]
        fullnode_rpc_port: Option<u16>,
        #[arg(short = 's', long)]
        fullnode_ssl: Option<String>,
        #[arg(short = 'n', long)]
        network: Option<String>,
        #[arg(short = 'a', long)]
        payout_address: Option<String>,
        #[arg(short = 'd', long = "plot-directory")]
        plot_directories: Option<Vec<String>>,
    },
    UpdatePoolInfo {},
}
impl Default for Action {
    fn default() -> Self {
        Action::Gui {}
    }
}

pub struct GenerateConfig<'a> {
    pub output_path: Option<PathBuf>,
    pub mnemonic: &'a str,
    pub fullnode_ws_host: Option<String>,
    pub fullnode_ws_port: Option<u16>,
    pub fullnode_rpc_host: Option<String>,
    pub fullnode_rpc_port: Option<u16>,
    pub fullnode_ssl: Option<String>,
    pub network: Option<String>,
    pub payout_address: Option<String>,
    pub plot_directories: Option<Vec<String>>,
    pub additional_headers: Option<HashMap<String, String>>,
}

pub async fn generate_config_from_mnemonic(
    gen_settings: GenerateConfig<'_>,
) -> Result<Config, Error> {
    if let Some(op) = &gen_settings.output_path {
        if op.exists()
            && !Confirm::new()
                .with_prompt(format!(
                    "An existing config exists at {:?}, would you like to override it? (Y/N)",
                    op
                ))
                .interact()
                .map_err(|e| {
                    Error::new(
                        ErrorKind::Interrupted,
                        format!("Dialog Interrupted: {:?}", e),
                    )
                })?
        {
            return Err(Error::new(ErrorKind::Interrupted, "User Canceled"));
        }
    }
    let mut config = Config::default();
    let network = gen_settings
        .network
        .map(|v| {
            if CONSENSUS_CONSTANTS_MAP.contains_key(&v) {
                v
            } else {
                "mainnet".to_string()
            }
        })
        .unwrap_or("mainnet".to_string());
    config.selected_network = network;
    config.payout_address = gen_settings.payout_address.unwrap_or_default();
    config.harvester_configs.bladebit = Some(BladebitHarvesterConfig {
        plot_directories: gen_settings.plot_directories.unwrap_or_default(),
    });
    let master_key = key_from_mnemonic(gen_settings.mnemonic)?;
    config.fullnode_ws_host = gen_settings
        .fullnode_ws_host
        .unwrap_or(String::from("localhost"));
    config.fullnode_rpc_host = gen_settings
        .fullnode_rpc_host
        .unwrap_or(String::from("localhost"));
    config.fullnode_ws_port = gen_settings.fullnode_ws_port.unwrap_or(8444);
    config.fullnode_rpc_port = gen_settings.fullnode_rpc_port.unwrap_or(8555);
    config.ssl_root_path = gen_settings.fullnode_ssl.clone();
    let client = FullnodeClient::new(
        &config.fullnode_rpc_host,
        config.fullnode_rpc_port,
        gen_settings.fullnode_ssl,
        &gen_settings.additional_headers,
    );
    let mut page = 0;
    let mut plot_nfts = vec![];
    while page < 50 && plot_nfts.is_empty() {
        let mut puzzle_hashes = vec![];
        for index in page * 50..(page + 1) * 50 {
            let wallet_sk = master_sk_to_wallet_sk_unhardened(&master_key, index).map_err(|e| {
                Error::new(
                    ErrorKind::InvalidInput,
                    format!("Failed to parse Wallet SK: {:?}", e),
                )
            })?;
            let pub_key: Bytes48 = wallet_sk.sk_to_pk().to_bytes().into();
            puzzle_hashes.push(puzzle_hash_for_pk(&pub_key)?);
            let hardened_wallet_sk = master_sk_to_wallet_sk(&master_key, index).map_err(|e| {
                Error::new(
                    ErrorKind::InvalidInput,
                    format!("Failed to parse Wallet SK: {:?}", e),
                )
            })?;
            let pub_key: Bytes48 = hardened_wallet_sk.sk_to_pk().to_bytes().into();
            puzzle_hashes.push(puzzle_hash_for_pk(&pub_key)?);
        }
        plot_nfts.extend(scrounge_for_plotnfts(&client, &puzzle_hashes).await?);
        page += 1;
    }
    for plot_nft in plot_nfts {
        config.pool_info.push(PoolWalletConfig {
            difficulty: None,
            launcher_id: plot_nft.launcher_id,
            pool_url: plot_nft.pool_state.pool_url.unwrap_or_default(),
            target_puzzle_hash: plot_nft.pool_state.target_puzzle_hash,
            p2_singleton_puzzle_hash: launcher_id_to_p2_puzzle_hash(
                &plot_nft.launcher_id,
                plot_nft.delay_time as u64,
                &plot_nft.delay_puzzle_hash,
            )?,
            owner_public_key: plot_nft.pool_state.owner_pubkey,
        });
        let mut owner_key = None;
        let mut auth_key = None;
        for i in 0..150 {
            let key = master_sk_to_singleton_owner_sk(&master_key, i).unwrap();
            let pub_key: Bytes48 = key.sk_to_pk().to_bytes().into();
            if pub_key == plot_nft.pool_state.owner_pubkey {
                let a_key = master_sk_to_pooling_authentication_sk(&master_key, i, 0).unwrap();
                owner_key = Some(key.into());
                auth_key = Some(a_key.into());
                break;
            }
        }
        if let Some(info) = config.farmer_info.iter_mut().find(|f| {
            if let Some(l) = &f.launcher_id {
                l == &plot_nft.launcher_id
            } else {
                false
            }
        }) {
            info.farmer_secret_key = master_sk_to_farmer_sk(&master_key)?.into();
            info.launcher_id = Some(plot_nft.launcher_id);
            info.owner_secret_key = owner_key;
            info.pool_secret_key = Some(master_sk_to_pool_sk(&master_key)?.into());
            info.auth_secret_key = auth_key;
        } else {
            config.farmer_info.push(FarmingInfo {
                farmer_secret_key: master_sk_to_farmer_sk(&master_key)?.into(),
                launcher_id: Some(plot_nft.launcher_id),
                pool_secret_key: Some(master_sk_to_pool_sk(&master_key)?.into()),
                owner_secret_key: owner_key,
                auth_secret_key: auth_key,
            });
        }
    }
    if let Some(op) = &gen_settings.output_path {
        config.save_as_yaml(op)?;
    }
    Ok(config)
}

pub async fn update_pool_info(config: Config) -> Result<Config, Error> {
    let client = FullnodeClient::new(
        &config.fullnode_rpc_host,
        config.fullnode_rpc_port,
        config.ssl_root_path.clone(),
        &None,
    );
    let mut plot_nfts = vec![];
    for farmer_info in &config.farmer_info {
        if let Some(launcher_id) = farmer_info.launcher_id {
            info!(
                "Fetching current PlotNFT state for launcher id {} ...",
                launcher_id.to_string()
            );
            plot_nfts.extend(get_plotnft_by_launcher_id(&client, &launcher_id).await?)
        }
    }

    let mut updated_config = config.clone();
    for plot_nft in plot_nfts {
        if let Some(pool_wallet) = updated_config
            .pool_info
            .iter_mut()
            .find(|pw| pw.launcher_id == plot_nft.launcher_id)
        {
            let old_pool_wallet = pool_wallet.clone();
            pool_wallet.pool_url = plot_nft.pool_state.pool_url.unwrap_or_default();
            if pool_wallet.target_puzzle_hash != plot_nft.pool_state.target_puzzle_hash {
                // Reset diff on pool change
                pool_wallet.difficulty = None;
            }
            pool_wallet.target_puzzle_hash = plot_nft.pool_state.target_puzzle_hash;
            pool_wallet.owner_public_key = plot_nft.pool_state.owner_pubkey;

            let mut change_messages: Vec<String> = vec![];
            if old_pool_wallet.pool_url != pool_wallet.pool_url {
                change_messages.push(format!(
                    "from {} to {}",
                    old_pool_wallet.pool_url, pool_wallet.pool_url
                ));
            }
            if old_pool_wallet.target_puzzle_hash != pool_wallet.target_puzzle_hash {
                change_messages.push(format!(
                    "from PH {} to PH {}",
                    old_pool_wallet.target_puzzle_hash, pool_wallet.target_puzzle_hash
                ));
            }
            if change_messages.is_empty() {
                info!(
                    "PlotNFT state for launcher id {} did not change",
                    plot_nft.launcher_id.to_string(),
                );
            } else {
                info!(
                    "PlotNFT state for launcher id {} did change {}",
                    plot_nft.launcher_id.to_string(),
                    change_messages.join(" and "),
                );
            }
        }
    }

    Ok(updated_config)
}
