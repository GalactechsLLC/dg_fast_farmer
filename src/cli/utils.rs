use crate::farmer::config::Config;
use crate::farmer::{CA_PRIVATE_CRT, PRIVATE_CRT, PRIVATE_KEY};
use dg_logger::{DruidGardenLogger, TimestampFormat};
use dg_xch_clients::ClientSSLConfig;
use dg_xch_clients::rpc::full_node::FullnodeClient as RpcClient;
use dg_xch_core::blockchain::sized_bytes::Bytes32;
use dg_xch_core::ssl::load_certs_from_bytes;
use dg_xch_core::traits::SizedBytes;
use dg_xch_core::utils::hash_256;
use home::home_dir;
use log::Level;
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;

pub(crate) fn get_root_path() -> PathBuf {
    let prefix = home_dir().unwrap_or(Path::new("/").to_path_buf());
    prefix.as_path().join(Path::new(".config/fast_farmer/"))
}

pub fn get_config_path() -> PathBuf {
    get_root_path()
        .as_path()
        .join(Path::new("fast_farmer.yaml"))
}

pub(crate) fn get_device_id_path() -> PathBuf {
    get_root_path().as_path().join(Path::new("device_id.bin"))
}

pub fn get_ssl_root_path<C: Clone>(config: &Config<C>) -> PathBuf {
    if let Some(ssl_root_path) = &config.ssl_root_path {
        PathBuf::from(ssl_root_path)
    } else {
        get_root_path().as_path().join(Path::new("ssl/"))
    }
}

pub(crate) fn rpc_client_from_config<C: Clone>(
    config: &Config<C>,
    headers: &Option<HashMap<String, String>>,
) -> Result<Arc<RpcClient>, Error> {
    Ok(Arc::new(RpcClient::new(
        &config.fullnode_rpc_host,
        config.fullnode_rpc_port,
        600,
        if is_community_node(config) {
            None
        } else {
            config.ssl_root_path.clone().map(|s| ClientSSLConfig {
                ssl_crt_path: Path::new(&s)
                    .join(PRIVATE_CRT)
                    .to_string_lossy()
                    .to_string(),
                ssl_key_path: Path::new(&s)
                    .join(PRIVATE_KEY)
                    .to_string_lossy()
                    .to_string(),
                ssl_ca_crt_path: Path::new(&s)
                    .join(CA_PRIVATE_CRT)
                    .to_string_lossy()
                    .to_string(),
            })
        },
        headers,
    )?))
}

pub async fn load_client_id<C: Clone>(config: Arc<RwLock<Config<C>>>) -> Result<Bytes32, Error> {
    let ssl_path = {
        let config = config.read().await;
        get_ssl_root_path(&*config).join(Path::new(crate::farmer::HARVESTER_CRT))
    };
    let cert_bytes = tokio::fs::read(&ssl_path).await?;
    let cert_chain = load_certs_from_bytes(&cert_bytes)?;
    let cert = cert_chain.first().ok_or(Error::new(
        ErrorKind::NotFound,
        format!("No Valid Cert found at {ssl_path:?}"),
    ))?;
    Ok(Bytes32::new(hash_256(cert)))
}

pub fn is_community_node<C: Clone>(config: &Config<C>) -> bool {
    ["druid.garden", "dev.druid.garden"]
        .contains(&config.fullnode_rpc_host.to_ascii_lowercase().trim())
}

pub fn init_logger() -> Result<Arc<DruidGardenLogger>, Error> {
    DruidGardenLogger::build()
        .use_colors(true)
        .current_level(Level::Info)
        .timestamp_format(TimestampFormat::Local)
        .init()
        .map_err(|e| Error::other(format!("{e:?}")))
}

pub fn check_config(config_path: &Path) -> Result<(), Error> {
    if !config_path.exists() {
        let error_msg = format!("Failed to find config at {config_path:?}, please run init");
        eprintln!("{error_msg}");
        Err(Error::new(ErrorKind::NotFound, error_msg))
    } else {
        Ok(())
    }
}
