use crate::farmer::config::Config;
use crate::farmer::{ExtendedFarmerSharedState, CA_PRIVATE_CRT, PRIVATE_CRT, PRIVATE_KEY};
use dg_xch_clients::rpc::full_node::FullnodeClient as RpcClient;
use dg_xch_clients::ClientSSLConfig;
use dg_xch_core::protocols::farmer::FarmerSharedState;
use home::home_dir;
use log::LevelFilter;
use simple_logger::SimpleLogger;
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::path::{Path, PathBuf};
use std::sync::Arc;

pub(crate) fn get_root_path() -> PathBuf {
    let prefix = home_dir().unwrap_or(Path::new("/").to_path_buf());
    prefix.as_path().join(Path::new(".config/fast_farmer/"))
}

pub(crate) fn get_config_path() -> PathBuf {
    get_root_path()
        .as_path()
        .join(Path::new("fast_farmer.yaml"))
}

pub(crate) fn get_device_id_path() -> PathBuf {
    get_root_path().as_path().join(Path::new("device_id.bin"))
}

pub(crate) fn get_ssl_root_path(
    shared_state: &FarmerSharedState<ExtendedFarmerSharedState>,
) -> PathBuf {
    if let Some(ssl_root_path) = &shared_state.data.config.ssl_root_path {
        PathBuf::from(ssl_root_path)
    } else {
        get_root_path().as_path().join(Path::new("ssl/"))
    }
}

pub(crate) fn rpc_client_from_config(
    config: &Config,
    headers: &Option<HashMap<String, String>>,
) -> Arc<RpcClient> {
    Arc::new(RpcClient::new(
        &config.fullnode_rpc_host,
        config.fullnode_rpc_port,
        600,
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
        }),
        headers,
    ))
}

pub(crate) fn init_logger() {
    SimpleLogger::new()
        .with_colors(true)
        .with_level(LevelFilter::Info)
        .env()
        .init()
        .unwrap_or_default();
}

pub(crate) fn check_config(config_path: &Path) -> Result<(), Error> {
    if !config_path.exists() {
        let error_msg = format!(
            "Failed to find config at {:?}, please run init",
            config_path
        );
        eprintln!("{error_msg}");
        Err(Error::new(ErrorKind::NotFound, error_msg))
    } else {
        Ok(())
    }
}
