use std::collections::HashMap;
use std::io::{Error};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use hex::encode;
use log::{debug, error, info, trace, warn};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio::sync::Mutex;
use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;
use dg_xch_clients::protocols::farmer::NewSignagePoint;
use dg_xch_clients::protocols::harvester::{PoolDifficulty};
use dg_xch_core::blockchain::proof_of_space::{calculate_pos_challenge, passes_plot_filter, ProofBytes, ProofOfSpace};
use dg_xch_core::blockchain::sized_bytes::{Bytes32, SizedBytes};
use dg_xch_core::consensus::constants::CONSENSUS_CONSTANTS_MAP;
use dg_xch_core::consensus::pot_iterations::{calculate_iterations_quality, calculate_sp_interval_iters, POOL_SUB_SLOT_ITERS};
use crate::models::config::Config;
use crate::models::PlotInfo;
use crate::models::protocol::ProofOfSpaceMsg;

pub async fn signatures_handler(
    mut signature_request_reciever: Receiver<(RequestSignedValues, Vec<PoolDifficulty>)>,
    new_proof_sender: Sender<ProofOfSpaceMsg>,
    config: Arc<Config>,
    plots: Arc<Mutex<HashMap<String, Arc<PlotInfo>>>>
) -> Result<(), Error> {
    while let Some(signage_point) = signage_reciever.recv().await {

    }
    Ok(())
}