use crate::cli::utils::rpc_client_from_config;
use crate::farmer::config::Config;
use crate::farmer::ExtendedFarmerSharedState;
use crate::gui::FullNodeState;
use dg_xch_clients::api::full_node::FullnodeAPI;
use dg_xch_core::protocols::farmer::FarmerSharedState;
use log::error;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub async fn update_blockchain(
    config: Arc<Config>,
    farmer_state: Arc<FarmerSharedState<ExtendedFarmerSharedState>>,
) {
    let full_node_rpc = rpc_client_from_config(config.as_ref(), &None);
    let mut last_update = Instant::now();
    loop {
        if last_update.elapsed().as_secs() > 5 {
            last_update = Instant::now();
            let bc_state = full_node_rpc.get_blockchain_state().await;
            match bc_state {
                Ok(bc_state) => {
                    farmer_state
                        .data
                        .extended_metrics
                        .blockchain_height
                        .set(bc_state.peak.as_ref().map(|p| p.height).unwrap_or_default() as u64);
                    farmer_state
                        .data
                        .extended_metrics
                        .blockchain_synced
                        .set(bc_state.sync.synced as u64);
                    farmer_state
                        .data
                        .extended_metrics
                        .blockchain_netspace
                        .set((bc_state.space / 1024u128 / 1024u128 / 1024u128) as u64); //Convert to GiB for better fitting into u64
                    *farmer_state.data.fullnode_state.write().await = Some(FullNodeState {
                        blockchain_state: bc_state,
                    });
                }
                Err(e) => {
                    error!("{:?}", e);
                }
            }
        }
        if !farmer_state.data.run.load(Ordering::Relaxed) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}
