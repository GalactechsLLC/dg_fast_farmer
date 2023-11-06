use crate::farmer::config::{Config, FarmingInfo, PoolWalletConfig};
use clap::{Parser, Subcommand};
use dg_xch_cli::wallets::plotnft_utils::scrounge_for_plotnfts;
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
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub action: Action,
    #[arg(short, long, value_name = "FILE")]
    pub config: Option<String>,
}

#[derive(Debug, Subcommand)]
pub enum Action {
    Run {},
    Init {
        #[arg(short, long)]
        mnemonic: String,
        #[arg(short = 'f', long)]
        fullnode_host: String,
        #[arg(short = 'p', long)]
        fullnode_port: u16,
        #[arg(short = 's', long)]
        fullnode_ssl: Option<String>,
        #[arg(short = 'n', long)]
        network: Option<String>,
    },
}

pub async fn generate_config_from_mnemonic(
    output_path: Option<PathBuf>,
    mnemonic: &str,
    fullnode_host: &str,
    fullnode_port: u16,
    fullnode_ssl: Option<String>,
    network: Option<String>,
    additional_headers: Option<HashMap<String, String>>,
) -> Result<Config, Error> {
    if let Some(op) = &output_path {
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
    let network = network
        .map(|v| {
            if CONSENSUS_CONSTANTS_MAP.contains_key(&v) {
                v
            } else {
                "mainnet".to_string()
            }
        })
        .unwrap_or("mainnet".to_string());
    config.selected_network = network;
    let master_key = key_from_mnemonic(mnemonic)?;
    config.fullnode_host = fullnode_host.to_string();
    config.fullnode_port = if fullnode_port == 8555 {
        8444
    } else {
        fullnode_port
    };
    config.ssl_root_path = fullnode_ssl.clone();
    let client = FullnodeClient::new(
        fullnode_host,
        fullnode_port,
        fullnode_ssl,
        &additional_headers,
    );
    let mut page = 0;
    let mut plotnfs = vec![];
    while page < 50 && plotnfs.is_empty() {
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
        plotnfs.extend(scrounge_for_plotnfts(&client, &puzzle_hashes).await?);
        page += 1;
    }
    for plot_nft in plotnfs {
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
    if let Some(op) = &output_path {
        config.save_as_yaml(op)?;
    }
    Ok(config)
}
