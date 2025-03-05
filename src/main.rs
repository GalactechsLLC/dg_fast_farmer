use dg_fast_farmer::harvesters::druid_garden::DruidGardenHarvester;
use dg_fast_farmer::{NewProofHandler, SignaturesHandler, cli};
use std::io::{Error, ErrorKind};
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let provider = rustls::crypto::ring::default_provider();
    provider.install_default().map_err(|_| {
        Error::new(
            ErrorKind::Other,
            "Failed to Install default Crypto Provider",
        )
    })?;
    cli::<(), DruidGardenHarvester<()>, (), NewProofHandler, SignaturesHandler>(Arc::new(())).await
}
