use dg_xch_core::blockchain::sized_bytes::{Bytes32, Bytes48};
use dg_xch_pos::plots::disk_plot::DiskPlot;
use dg_xch_pos::plots::plot_reader::PlotReader;
use tokio::fs::File;

pub mod config;

#[derive(Debug, Clone)]
pub struct PlotInfo {
    pub prover: PlotReader<File, DiskPlot<File>>,
    pub pool_public_key: Option<Bytes48>,
    pub pool_contract_puzzle_hash: Option<Bytes32>,
    pub plot_public_key: Bytes48,
    pub file_size: usize,
    pub time_modified: usize,
}

#[derive(Debug)]
pub struct FarmerIdentifier {
    pub plot_identifier: String,
    pub challenge_hash: Bytes32,
    pub sp_hash: Bytes32,
}