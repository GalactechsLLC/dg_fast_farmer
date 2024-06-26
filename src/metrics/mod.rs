use crate::_version;
use crate::cli::utils::get_device_id_path;
use crate::farmer::ExtendedFarmerSharedState;
use actix_web::web::{Data, Json, ServiceConfig};
use actix_web::{get, Error, HttpResponse};
use dg_xch_core::protocols::farmer::FarmerSharedState;
use log::{debug, info};
use prometheus::core::{
    AtomicU64, GenericCounter, GenericCounterVec, GenericGauge, GenericGaugeVec,
};
use prometheus::{Histogram, HistogramOpts, Opts, Registry, TextEncoder};
use protobuf::Message;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::ErrorKind;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use uuid::Uuid;

const PLOT_LOAD_LATENCY_BUCKETS: [f64; 11] = [
    0.01,
    0.05,
    0.1,
    0.25,
    0.5,
    1.0,
    2.5,
    5.0,
    10.0,
    30.0,
    f64::INFINITY,
];
const LATENCY_BUCKETS: [f64; 11] = [
    0.01,
    0.05,
    0.1,
    0.25,
    0.5,
    1.0,
    2.5,
    5.0,
    10.0,
    30.0,
    f64::INFINITY,
];
const SP_INTERVAL_BUCKETS: [f64; 11] = [
    0f64,
    4f64,
    8f64,
    12f64,
    16f64,
    20f64,
    25f64,
    30f64,
    45f64,
    60f64,
    f64::INFINITY,
];

pub struct Metrics {
    pub id: Uuid,
    pub registry: Arc<RwLock<Registry>>,
    pub qualities_latency: Arc<Histogram>,
    pub proof_latency: Arc<Histogram>,
    pub signage_point_interval: Arc<Histogram>,
    pub signage_point_processing_latency: Arc<Histogram>,
    pub plot_load_latency: Arc<Histogram>,
    pub blockchain_synced: Arc<GenericGauge<AtomicU64>>,
    pub blockchain_height: Arc<GenericGauge<AtomicU64>>,
    pub blockchain_netspace: Arc<GenericGauge<AtomicU64>>,
    pub total_proofs_found: Arc<GenericCounter<AtomicU64>>,
    pub last_proofs_found: Arc<GenericGauge<AtomicU64>>,
    pub total_partials_found: Arc<GenericCounter<AtomicU64>>,
    pub last_partials_found: Arc<GenericGauge<AtomicU64>>,
    pub total_passed_filter: Arc<GenericCounter<AtomicU64>>,
    pub last_passed_filter: Arc<GenericGauge<AtomicU64>>,
    pub partials_submitted: Arc<GenericCounterVec<AtomicU64>>,
    pub plot_file_size: Arc<GenericGaugeVec<AtomicU64>>,
    pub plot_counts: Arc<GenericGaugeVec<AtomicU64>>,
}
impl Default for Metrics {
    fn default() -> Self {
        let id = get_uuid().unwrap_or_else(|_| Uuid::new_v4());
        let metrics_registry = Registry::new_custom(
            Some(String::from("fast_farmer")),
            Some(HashMap::from([
                ("device_id".to_string(), id.to_string()),
                ("fast_farmer_version".to_string(), _version().to_string()),
            ])),
        )
        .expect("Expected To Create Default Metrics Registry");
        Self {
            id,
            blockchain_synced: Arc::new(
                GenericGauge::new("blockchain_synced", "Is Upstream Node Synced")
                    .map(|g: GenericGauge<AtomicU64>| {
                        metrics_registry.register(Box::new(g.clone())).unwrap_or(());
                        g
                    })
                    .expect("Expected To Create Static Metrics"),
            ),
            blockchain_height: Arc::new(
                GenericGauge::new("blockchain_height", "Blockchain Height")
                    .map(|g: GenericGauge<AtomicU64>| {
                        metrics_registry.register(Box::new(g.clone())).unwrap_or(());
                        g
                    })
                    .expect("Expected To Create Static Metrics"),
            ),
            blockchain_netspace: Arc::new(
                GenericGauge::new("blockchain_netspace", "Current Netspace")
                    .map(|g: GenericGauge<AtomicU64>| {
                        metrics_registry.register(Box::new(g.clone())).unwrap_or(());
                        g
                    })
                    .expect("Expected To Create Static Metrics"),
            ),
            qualities_latency: Arc::new({
                let opts = HistogramOpts::new(
                    "qualities_latency",
                    "Time in seconds to load plot data from Disk",
                )
                .buckets(LATENCY_BUCKETS.to_vec());
                Histogram::with_opts(opts)
                    .map(|h: Histogram| {
                        metrics_registry.register(Box::new(h.clone())).unwrap_or(());
                        h
                    })
                    .expect("Expected To Create Static Metrics")
            }),
            proof_latency: Arc::new({
                let opts = HistogramOpts::new(
                    "proof_latency",
                    "Time in seconds to compute a proof/partial",
                )
                .buckets(LATENCY_BUCKETS.to_vec());
                Histogram::with_opts(opts)
                    .map(|h: Histogram| {
                        metrics_registry.register(Box::new(h.clone())).unwrap_or(());
                        h
                    })
                    .expect("Expected To Create Static Metrics")
            }),
            signage_point_interval: Arc::new({
                let opts = HistogramOpts::new(
                    "signage_point_interval",
                    "Time in seconds in between signage points",
                )
                .buckets(SP_INTERVAL_BUCKETS.to_vec());
                Histogram::with_opts(opts)
                    .map(|h: Histogram| {
                        metrics_registry.register(Box::new(h.clone())).unwrap_or(());
                        h
                    })
                    .expect("Expected To Create Static Metrics")
            }),
            signage_point_processing_latency: Arc::new({
                let opts = HistogramOpts::new(
                    "signage_point_processing_latency",
                    "Time in seconds to process signage points",
                )
                .buckets(LATENCY_BUCKETS.to_vec());
                Histogram::with_opts(opts)
                    .map(|h: Histogram| {
                        metrics_registry.register(Box::new(h.clone())).unwrap_or(());
                        h
                    })
                    .expect("Expected To Create Static Metrics")
            }),
            plot_load_latency: Arc::new({
                let opts = HistogramOpts::new(
                    "plot_load_latency",
                    "Time in seconds to compute a plot file",
                )
                .buckets(PLOT_LOAD_LATENCY_BUCKETS.to_vec());
                Histogram::with_opts(opts)
                    .map(|h: Histogram| {
                        metrics_registry.register(Box::new(h.clone())).unwrap_or(());
                        h
                    })
                    .expect("Expected To Create Static Metrics")
            }),
            partials_submitted: Arc::new(
                GenericCounterVec::new(
                    Opts::new("partials_submitted", "Total Partials Submitted"),
                    &["launcher_id"],
                )
                .map(|g: GenericCounterVec<AtomicU64>| {
                    metrics_registry.register(Box::new(g.clone())).unwrap_or(());
                    g
                })
                .expect("Expected To Create Static Metrics"),
            ),
            total_proofs_found: Arc::new(
                GenericCounter::new("total_proofs_found", "Total Proofs Found")
                    .map(|g: GenericCounter<AtomicU64>| {
                        metrics_registry.register(Box::new(g.clone())).unwrap_or(());
                        g
                    })
                    .expect("Expected To Create Static Metrics"),
            ),
            last_proofs_found: Arc::new(
                GenericGauge::new("last_proofs_found", "Last Value of Proofs Found")
                    .map(|g: GenericGauge<AtomicU64>| {
                        metrics_registry.register(Box::new(g.clone())).unwrap_or(());
                        g
                    })
                    .expect("Expected To Create Static Metrics"),
            ),
            total_partials_found: Arc::new(
                GenericCounter::new("total_partials_found", "Total Partials Found")
                    .map(|g: GenericCounter<AtomicU64>| {
                        metrics_registry.register(Box::new(g.clone())).unwrap_or(());
                        g
                    })
                    .expect("Expected To Create Static Metrics"),
            ),
            last_partials_found: Arc::new(
                GenericGauge::new("last_partials_found", "Last Value of Partials Found")
                    .map(|g: GenericGauge<AtomicU64>| {
                        metrics_registry.register(Box::new(g.clone())).unwrap_or(());
                        g
                    })
                    .expect("Expected To Create Static Metrics"),
            ),
            total_passed_filter: Arc::new(
                GenericCounter::new("total_passed_filter", "Total Plots Passed Filter")
                    .map(|g: GenericCounter<AtomicU64>| {
                        metrics_registry.register(Box::new(g.clone())).unwrap_or(());
                        g
                    })
                    .expect("Expected To Create Static Metrics"),
            ),
            last_passed_filter: Arc::new(
                GenericGauge::new("last_passed_filter", "Last Value of Plots Passed Filter")
                    .map(|g: GenericGauge<AtomicU64>| {
                        metrics_registry.register(Box::new(g.clone())).unwrap_or(());
                        g
                    })
                    .expect("Expected To Create Static Metrics"),
            ),
            plot_file_size: Arc::new(
                GenericGaugeVec::new(
                    Opts::new("plot_file_size", "Plots Loaded on Server"),
                    &["c_level", "k_size", "type"],
                )
                .map(|g: GenericGaugeVec<AtomicU64>| {
                    metrics_registry.register(Box::new(g.clone())).unwrap_or(());
                    g
                })
                .expect("Expected To Create Static Metrics"),
            ),
            plot_counts: Arc::new(
                GenericGaugeVec::new(
                    Opts::new("plot_counts", "Plots Loaded on Server"),
                    &["c_level", "k_size", "type"],
                )
                .map(|g: GenericGaugeVec<AtomicU64>| {
                    metrics_registry.register(Box::new(g.clone())).unwrap_or(());
                    g
                })
                .expect("Expected To Create Static Metrics"),
            ),
            registry: Arc::new(RwLock::new(metrics_registry)),
        }
    }
}

pub fn init(cfg: &mut ServiceConfig) {
    cfg.service(metrics);
    cfg.service(bin_metrics);
}

#[get("/metrics")]
pub async fn metrics(
    state: Data<Arc<FarmerSharedState<ExtendedFarmerSharedState>>>,
) -> Result<HttpResponse, Error> {
    if let Some(farmer_metrics) = state.metrics.read().await.as_ref() {
        if let Some(uptime) = &farmer_metrics.uptime {
            uptime.set(
                Instant::now()
                    .duration_since(*farmer_metrics.start_time)
                    .as_secs(),
            )
        }
    }
    let encoder = TextEncoder::new();
    match encoder.encode_to_string(&state.data.extended_metrics.registry.read().await.gather()) {
        Ok(enc) => Ok(HttpResponse::Ok().body(enc)),
        Err(err) => {
            debug!("Error in metrics: {:?}", err);
            Ok(HttpResponse::InternalServerError().finish())
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct MetricsResp {
    pub metrics: Vec<Vec<u8>>,
}

#[get("/metrics/bin")]
pub async fn bin_metrics(
    state: Data<Arc<FarmerSharedState<ExtendedFarmerSharedState>>>,
) -> Result<Json<MetricsResp>, Error> {
    if let Some(farmer_metrics) = state.metrics.read().await.as_ref() {
        if let Some(uptime) = &farmer_metrics.uptime {
            uptime.set(
                Instant::now()
                    .duration_since(*farmer_metrics.start_time)
                    .as_secs(),
            )
        }
    }
    Ok(Json(MetricsResp {
        metrics: state
            .data
            .extended_metrics
            .registry
            .read()
            .await
            .gather()
            .into_iter()
            .map(|m| m.write_to_bytes().unwrap_or_default())
            .collect(),
    }))
}

pub fn get_uuid() -> Result<Uuid, std::io::Error> {
    let uuid_path = get_device_id_path();
    if uuid_path.exists() {
        Uuid::parse_str(fs::read_to_string(uuid_path)?.as_str())
            .map_err(|e| std::io::Error::new(ErrorKind::InvalidInput, e))
    } else {
        info!("Creating UUID: {:?}", uuid_path);
        if let Some(p) = &uuid_path.parent() {
            fs::create_dir_all(p)?;
        }
        let uuid = Uuid::new_v4();
        match fs::write(&uuid_path, uuid.to_string().as_bytes()) {
            Ok(_) => Uuid::parse_str(fs::read_to_string(uuid_path)?.as_str())
                .map_err(|e| std::io::Error::new(ErrorKind::InvalidInput, e)),
            Err(e) => Err(std::io::Error::new(ErrorKind::InvalidInput, e)),
        }
    }
}
