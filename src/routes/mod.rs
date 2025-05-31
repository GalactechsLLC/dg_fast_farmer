use dg_logger::DruidGardenLogger;
use dg_xch_core::blockchain::blockchain_state::BlockchainState;
use dg_xch_core::protocols::farmer::{FarmerSharedState, FarmerStats, SerialPlotCounts};
use log::{Level, debug, error, info};
use portfu::macros::{get, websocket};
use portfu::prelude::http::HeaderValue;
use portfu::prelude::http::header::CONTENT_TYPE;
use portfu::prelude::tokio_tungstenite::tungstenite::Message;
use portfu::prelude::*;
use prometheus::TextEncoder;
use serde::{Deserialize, Serialize};
use std::io::{Error, ErrorKind};
use std::str::FromStr;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};
use time::OffsetDateTime;

#[get("/metrics")]
pub async fn metrics<T: Sync + Send + 'static>(
    state: State<FarmerSharedState<T>>,
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
) -> Result<Vec<FarmerStats>, Error> {
    let mut data = Vec::default();
    let lock = state.0.recent_plot_stats.read().await;
    for val in lock.keys().iter().zip(lock.values()) {
        if let (Some(k), Some(v)) = val {
            data.push(FarmerStats {
                challenge_hash: k.1,
                sp_hash: k.0,
                running: true,
                og_passed_filter: v.og_passed,
                og_plot_count: v.og_total,
                nft_passed_filter: v.pool_passed,
                nft_plot_count: v.pool_total,
                compressed_passed_filter: v.compressed_passed,
                compressed_plot_count: v.compressed_total,
                invalid_plot_count: state
                    .0
                    .plot_counts
                    .invalid_plot_count
                    .load(Ordering::Relaxed),
                proofs_found: v.proofs_found,
                total_plot_space: state.0.plot_counts.total_plot_space.load(Ordering::Relaxed),
                full_node_height: state
                    .0
                    .fullnode_state
                    .read()
                    .await
                    .as_ref()
                    .map(|v| v.peak.as_ref().map(|v| v.height as i64).unwrap_or_default())
                    .unwrap_or_default(),
                full_node_difficulty: state
                    .0
                    .fullnode_state
                    .read()
                    .await
                    .as_ref()
                    .map(|v| v.difficulty)
                    .unwrap_or_default() as i64,
                full_node_synced: state
                    .0
                    .fullnode_state
                    .read()
                    .await
                    .as_ref()
                    .map(|v| v.sync.synced)
                    .unwrap_or_default(),
                gathered: OffsetDateTime::now_utc(),
            });
        }
    }
    Ok(data)
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
        msgs.push(Message::Text(serde_json::to_string(msg)?.into()));
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
                            if let Err(e) = socket.send(Message::Text(as_json.into())).await {
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
