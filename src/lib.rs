use crate::cli::commands::{cli_mode, tui_mode};
use crate::farmer::ExtendedFarmerSharedState;
use dg_xch_core::protocols::farmer::FarmerSharedState;
use dg_xch_serialize::ChiaProtocolVersion;
use once_cell::sync::Lazy;
use portfu::prelude::http::header::USER_AGENT;
use std::collections::HashMap;
use std::io::Error;
use std::sync::Arc;

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

pub async fn run(args: RunArgs<ExtendedFarmerSharedState>) -> Result<(), Error> {
    match args.mode {
        RunMode::Cli => cli_mode(args.shared_state).await,
        RunMode::Tui => tui_mode(args.shared_state).await,
    }
}
