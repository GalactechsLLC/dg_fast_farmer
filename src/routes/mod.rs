use dg_logger::DruidGardenLogger;
use dg_xch_core::blockchain::blockchain_state::BlockchainState;
use dg_xch_core::blockchain::sized_bytes::Bytes32;
use dg_xch_core::protocols::farmer::{FarmerSharedState, FarmerStats, PlotCounts};
use log::{Level, debug, error, info};
use portfu::macros::{get, websocket};
use portfu::prelude::http::HeaderValue;
use portfu::prelude::http::header::CONTENT_TYPE;
use portfu::prelude::tokio_tungstenite::tungstenite::Message;
use portfu::prelude::*;
use prometheus::TextEncoder;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Error, ErrorKind};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

#[get("/metrics")]
pub async fn metrics<T: Sync + Send + 'static>(
    state: State<Arc<FarmerSharedState<T>>>,
    data: &mut ServiceData,
) -> Result<String, Error> {
    if let Some(farmer_metrics) = state.0.metrics.read().await.as_ref() {
        farmer_metrics.uptime.set(
            Instant::now()
                .duration_since(*farmer_metrics.start_time)
                .as_secs(),
        );
    }
    data.response.headers_mut().insert(
        CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4"),
    );
    if let Some(m) = state.0.metrics.read().await.as_ref() {
        let encoder = TextEncoder::new();
        encoder
            .encode_to_string(&m.registry.read().await.gather())
            .map_err(|e| {
                Error::new(
                    ErrorKind::InvalidData,
                    format!("Failed to Gather Metrics Data: {e:?}"),
                )
            })
    } else {
        Err(Error::new(ErrorKind::NotFound, "No routes were created"))
    }
}

#[derive(Serialize, Deserialize)]
pub struct SerialPlotCounts {
    pub og_plot_count: u64,
    pub nft_plot_count: u64,
    pub compresses_plot_count: u64,
    pub invalid_plot_count: u64,
    pub total_plot_space: u64,
}
impl From<&PlotCounts> for SerialPlotCounts {
    fn from(counts: &PlotCounts) -> Self {
        Self {
            og_plot_count: counts.og_plot_count.load(Ordering::Relaxed),
            nft_plot_count: counts.nft_plot_count.load(Ordering::Relaxed),
            compresses_plot_count: counts.compresses_plot_count.load(Ordering::Relaxed),
            invalid_plot_count: counts.invalid_plot_count.load(Ordering::Relaxed),
            total_plot_space: counts.total_plot_space.load(Ordering::Relaxed),
        }
    }
}

use crate::harvesters::druid_garden::PlotCounts as HarvesterPlotCounts;
#[derive(Serialize, Deserialize)]
pub struct SerialHarvesterPlotCounts {
    pub og_passed: u64,
    pub og_total: u64,
    pub pool_total: u64,
    pub pool_passed: u64,
    pub compressed_passed: u64,
    pub compressed_total: u64,
}
impl From<&HarvesterPlotCounts> for SerialHarvesterPlotCounts {
    fn from(counts: &HarvesterPlotCounts) -> Self {
        Self {
            og_passed: counts.og_passed.load(Ordering::Relaxed),
            og_total: counts.og_total.load(Ordering::Relaxed),
            pool_total: counts.pool_total.load(Ordering::Relaxed),
            pool_passed: counts.pool_passed.load(Ordering::Relaxed),
            compressed_passed: counts.compressed_passed.load(Ordering::Relaxed),
            compressed_total: counts.compressed_total.load(Ordering::Relaxed),
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct FarmerPublicState {
    pub running: bool,
    pub plot_counts: SerialPlotCounts,
    pub blockchain_state: Option<BlockchainState>,
}

#[get("/state", output = "json", eoutput = "bytes")]
pub async fn farmer_state<T: Sync + Send + 'static>(
    state: State<FarmerSharedState<T>>,
) -> Result<FarmerPublicState, Error> {
    Ok(FarmerPublicState {
        running: state.0.signal.load(Ordering::Relaxed),
        plot_counts: state.0.plot_counts.as_ref().into(),
        blockchain_state: state
            .0
            .fullnode_state
            .read()
            .await
            .as_ref()
            .map(|v| v.clone()),
    })
}

#[get("/stats", output = "json", eoutput = "bytes")]
pub async fn farmer_stats<T: Sync + Send + 'static>(
    state: State<FarmerSharedState<T>>,
) -> Result<HashMap<(Bytes32, Bytes32), FarmerStats>, Error> {
    Ok(state.0.recent_stats.read().await.clone())
}

#[websocket("/log_stream/{level}")]
pub async fn log_stream(
    socket: WebSocket,
    level: Path,
    logger: State<DruidGardenLogger>,
) -> Result<(), Error> {
    let mut err = None;
    let level = level.inner();
    let level = Level::from_str(level.as_str()).map_err(|e| {
        Error::new(
            ErrorKind::InvalidInput,
            format!("{} is not a valid Log Level: {e:?}", level),
        )
    })?;
    let mut msgs = vec![];
    for msg in logger.0.buffer.read().await.iter() {
        msgs.push(Message::Text(serde_json::to_string(msg)?));
    }
    let mut receiver = logger.0.subscribe();
    socket.send_all(msgs).await?;
    loop {
        tokio::select! {
            result = receiver.recv() => {
                match result {
                    Ok(log_entry) => {
                        if log_entry.level <= level {
                            let as_json = serde_json::to_string(&log_entry)?;
                            if let Err(e) = socket.send(Message::Text(as_json)).await {
                                debug!("Failed to send log entry: {e:?}");
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to read message from log channel: {e:?}");
                        break;
                    }
                }
            }
            result = socket.next() => {
                match result {
                    Ok(Some(msg)) => {
                        match msg {
                            Message::Ping(ping_data) => {
                                socket.send(Message::Pong(ping_data)).await?;
                            }
                            Message::Pong(_) | Message::Frame(_) |
                            Message::Binary(_) | Message::Text(_) => {
                                //Ignore Client Messages
                                continue;
                            }
                            Message::Close(_close_msg) => {
                                info!("Stream received Close");
                                break;
                            }
                        }
                    }
                    Ok(None) => {
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    },
                    Err(e) => {
                        err = Some(e);
                        break
                    },
                }
            }
        }
    }
    match err {
        Some(e) => Err(e),
        None => Ok(()),
    }
}
