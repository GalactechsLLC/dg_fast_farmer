pub(crate) mod commands;
mod prompts;
pub(crate) mod utils;

use clap::{Parser, Subcommand};
use std::io::Error;
use std::str::FromStr;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub action: Option<Action>,
    #[arg(short, long, value_name = "FILE")]
    pub config: Option<String>,
}

#[derive(Default, Debug, Copy, Clone, Subcommand)]
pub enum RunMode {
    Cli,
    #[default]
    Tui,
}
impl FromStr for RunMode {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.to_ascii_lowercase().as_str() {
            "cli" => RunMode::Cli,
            "tui" => RunMode::Tui,
            _ => RunMode::default(),
        })
    }
}

#[derive(Debug, Subcommand)]
pub enum Action {
    Run {
        #[arg(short = 'm', long)]
        mode: Option<RunMode>,
    },
    Init {
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
        #[arg(short = 'm', long)]
        mnemonic_file: Option<String>,
        #[arg(short = 'l', long)]
        launcher_id: Option<String>,
    },
    Update {},
    UpdatePoolInfo {
        #[arg(short = 'l', long)]
        launcher_id: Option<String>,
    },
    UpdatePayoutAddress {
        #[arg(short = 'a', long)]
        address: String,
    },
    JoinPool {
        #[arg(short = 'u', long)]
        pool_url: String,
        #[arg(short = 'm', long)]
        mnemonic_file: Option<String>,
        #[arg(short = 'i', long)]
        launcher_id: Option<String>,
        #[arg(short = 'f', long)]
        fee: Option<u64>,
    },
}
impl Default for Action {
    fn default() -> Self {
        Action::Run {
            mode: Some(RunMode::default()),
        }
    }
}
