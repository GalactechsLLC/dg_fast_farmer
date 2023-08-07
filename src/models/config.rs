use std::collections::HashMap;
use std::fs;
use std::io::{Error, ErrorKind};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use blst::min_pk::SecretKey;
use dg_xch_core::blockchain::sized_bytes::{Bytes32, Bytes48, hex_to_bytes};

#[derive(
Default, Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
pub struct FarmingInfo {
    pub farmer_secret_key: String,
    pub launcher_id: Option<String>,
    pub pool_secret_key: Option<String>,
    pub owner_secret_key: Option<String>,
    pub auth_secret_key: Option<String>,
}

#[derive(
Default, Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize,
)]
pub struct PoolWalletConfig {
    pub launcher_id: Bytes32,
    pub pool_url: String,
    pub payout_instructions: String,
    pub target_puzzle_hash: Bytes32,
    pub p2_singleton_puzzle_hash: Bytes32,
    pub owner_public_key: Bytes48,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Config {
    pub selected_network: String,
    pub ssl_root_path: Option<String>,
    pub fullnode_host: String,
    pub fullnode_port: u16,
    pub farmer_info: Vec<FarmingInfo>,
    pub pool_info: Vec<PoolWalletConfig>,
    pub plot_directories: Vec<String>,
    pub payout_address: String,
    pub farmer_name: String,
}
impl TryFrom<&Path> for Config {
    type Error = Error;
    fn try_from(value: &Path) -> Result<Self, Self::Error> {
        serde_yaml::from_str::<Config>(&fs::read_to_string(value)?)
            .map_err(|e| Error::new(ErrorKind::Other, format!("{:?}", e)))
    }
}
impl TryFrom<&PathBuf> for Config {
    type Error = Error;
    fn try_from(value: &PathBuf) -> Result<Self, Self::Error> {
        Self::try_from(value.as_path())
    }
}

pub async fn load_keys(config: Arc<Config>) -> (Vec<SecretKey>, HashMap<Bytes48, SecretKey>, HashMap<Bytes48, SecretKey>){
    let mut farmer_secret_keys = vec![];
    let mut owner_secret_keys = HashMap::default();
    let mut pool_public_keys = HashMap::default();
    for farmer_info in config.farmer_info.iter() {
        if let Ok(bytes) = hex_to_bytes(&farmer_info.farmer_secret_key) {
            if let Ok(sec_key) = SecretKey::from_bytes(&bytes) {
                farmer_secret_keys.push(sec_key)
            }
        }
        if let Some(key) = &farmer_info.pool_secret_key {
            if let Ok(bytes) = hex_to_bytes(key) {
                if let Ok(sec_key) = SecretKey::from_bytes(&bytes) {
                    pool_public_keys
                        .insert(sec_key.sk_to_pk().to_bytes().into(), sec_key.clone());
                }
            }
        }
        if let Some(key) = &farmer_info.owner_secret_key {
            if let Ok(bytes) = hex_to_bytes(key) {
                if let Ok(sec_key) = SecretKey::from_bytes(&bytes) {
                    owner_secret_keys
                        .insert(sec_key.sk_to_pk().to_bytes().into(), sec_key.clone());
                }
            }
        }
    }
    (farmer_secret_keys, owner_secret_keys, pool_public_keys)
}