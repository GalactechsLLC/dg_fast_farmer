use crate::farmer::protocols::harvester::respond_signatures::RespondSignaturesHandler;
use crate::farmer::FarmerSharedState;
use crate::harvesters::{Harvester, Harvesters};
use async_trait::async_trait;
use dg_xch_clients::api::pool::PoolClient;
use dg_xch_clients::protocols::farmer::RequestSignedValues;
use dg_xch_clients::protocols::harvester::RequestSignatures;
use dg_xch_clients::websocket::{ChiaMessage, MessageHandler};
use dg_xch_core::consensus::constants::ConsensusConstants;
use dg_xch_serialize::ChiaSerialize;
use log::error;
use std::collections::HashMap;
use std::io::{Cursor, Error, ErrorKind};
use std::sync::Arc;
use uuid::Uuid;

pub struct RequestSignedValuesHandle<T: PoolClient + Sized + Sync + Send + 'static> {
    pub id: Uuid,
    pub shared_state: Arc<FarmerSharedState>,
    pub pool_client: Arc<T>,
    pub harvesters: Arc<HashMap<Uuid, Arc<Harvesters>>>,
    pub constants: &'static ConsensusConstants,
}
#[async_trait]
impl<T: PoolClient + Sized + Sync + Send + 'static> MessageHandler
    for RequestSignedValuesHandle<T>
{
    async fn handle(&self, msg: Arc<ChiaMessage>) -> Result<(), Error> {
        let mut cursor = Cursor::new(&msg.data);
        let request = RequestSignedValues::from_bytes(&mut cursor)?;
        if let Some(identifier) = self
            .shared_state
            .quality_to_identifiers
            .lock()
            .await
            .get(&request.quality_string)
        {
            let request = RequestSignatures {
                plot_identifier: identifier.plot_identifier.clone(),
                challenge_hash: identifier.challenge_hash,
                sp_hash: identifier.sp_hash,
                messages: vec![
                    request.foliage_block_data_hash,
                    request.foliage_transaction_block_hash,
                ],
            };
            let sig_handle = RespondSignaturesHandler {
                pool_client: self.pool_client.clone(),
                shared_state: self.shared_state.clone(),
                harvester_id: identifier.harvester_id,
                harvesters: self.harvesters.clone(),
                constants: self.constants,
            };
            if let Some(h) = self.harvesters.get(&identifier.harvester_id) {
                let harvester = h.clone();
                tokio::spawn(async move {
                    match harvester.as_ref() {
                        Harvesters::DruidGarden(harvester) => {
                            harvester.request_signatures(request, sig_handle).await?;
                        }
                    }
                    Ok::<(), Error>(())
                });
            }
            Ok(())
        } else {
            error!("Do not have quality {}", &request.quality_string);
            Err(Error::new(
                ErrorKind::NotFound,
                format!("Do not have quality {}", &request.quality_string),
            ))
        }
    }
}
