use std::io::{Error, ErrorKind};
use dg_fast_farmer::cli;
use dg_fast_farmer::harvesters::Harvesters;

#[tokio::main]
async fn main() -> Result<(), Error> {
    let provider = rustls::crypto::ring::default_provider();
    provider.install_default().map_err(|_| {
        Error::new(
            ErrorKind::Other,
            "Failed to Install default Crypto Provider",
        )
    })?;
    cli::<(), Harvesters<()>, ()>(()).await
}
