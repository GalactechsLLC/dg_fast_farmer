use crate::_version;
use crate::cli::utils::get_device_id_path;
use crate::farmer::ExtendedFarmerSharedState;
use dg_xch_core::protocols::farmer::{FarmerMetrics, FarmerSharedState};
use log::info;
use portfu::macros::get;
use portfu::prelude::http::HeaderValue;
use portfu::prelude::http::header::CONTENT_TYPE;
use portfu::prelude::*;
use prometheus::{Registry, TextEncoder};
use std::collections::HashMap;
use std::fs;
use std::io::{Error, ErrorKind};
use std::sync::Arc;
use std::time::Instant;
use uuid::Uuid;

pub fn get_metrics() -> FarmerMetrics {
    let id = get_uuid().unwrap_or_else(|_| Uuid::new_v4());
    let metrics_registry = Registry::new_custom(
        Some(String::from("fast_farmer")),
        Some(HashMap::from([
            ("device_id".to_string(), id.to_string()),
            ("fast_farmer_version".to_string(), _version().to_string()),
        ])),
    )
    .expect("Expected To Create Default Metrics Registry");
    FarmerMetrics::new(metrics_registry, id)
}

#[get("/metrics")]
pub async fn metrics(
    state: State<Arc<FarmerSharedState<ExtendedFarmerSharedState>>>,
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
        Err(Error::new(ErrorKind::NotFound, "No metrics were created"))
    }
}

pub fn get_uuid() -> Result<Uuid, Error> {
    let uuid_path = get_device_id_path();
    if uuid_path.exists() {
        Uuid::parse_str(fs::read_to_string(uuid_path)?.as_str())
            .map_err(|e| Error::new(ErrorKind::InvalidInput, e))
    } else {
        info!("Creating UUID: {:?}", uuid_path);
        if let Some(p) = &uuid_path.parent() {
            fs::create_dir_all(p)?;
        }
        let uuid = Uuid::new_v4();
        match fs::write(&uuid_path, uuid.to_string().as_bytes()) {
            Ok(_) => Uuid::parse_str(fs::read_to_string(uuid_path)?.as_str())
                .map_err(|e| Error::new(ErrorKind::InvalidInput, e)),
            Err(e) => Err(Error::new(ErrorKind::InvalidInput, e)),
        }
    }
}
