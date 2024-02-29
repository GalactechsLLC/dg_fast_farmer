use crate::farmer::protocols::harvester::respond_signatures::RespondSignaturesHandler;
use crate::farmer::{ExtendedFarmerSharedState, FarmerSharedState};
use crate::harvesters::{Harvester, Harvesters};
use async_trait::async_trait;
use dg_xch_clients::api::pool::PoolClient;
use dg_xch_core::blockchain::sized_bytes::Bytes32;
use dg_xch_core::consensus::constants::ConsensusConstants;
use dg_xch_core::protocols::farmer::RequestSignedValues;
use dg_xch_core::protocols::harvester::{
    RequestSignatures, SignatureRequestSourceData, SigningDataKind,
};
use dg_xch_core::protocols::{ChiaMessage, MessageHandler, PeerMap};
use dg_xch_serialize::ChiaSerialize;
use log::{debug, error};
use std::collections::HashMap;
use std::io::{Cursor, Error, ErrorKind};
use std::sync::Arc;
use uuid::Uuid;

pub struct RequestSignedValuesHandle<T: PoolClient + Sized + Sync + Send + 'static> {
    pub id: Uuid,
    pub shared_state: Arc<FarmerSharedState<ExtendedFarmerSharedState>>,
    pub pool_client: Arc<T>,
    pub harvesters: Arc<HashMap<Bytes32, Arc<Harvesters>>>,
    pub constants: &'static ConsensusConstants,
}
#[async_trait]
impl<T: PoolClient + Sized + Sync + Send + 'static> MessageHandler
    for RequestSignedValuesHandle<T>
{
    async fn handle(
        &self,
        msg: Arc<ChiaMessage>,
        _peer_id: Arc<Bytes32>,
        _peers: PeerMap,
    ) -> Result<(), Error> {
        debug!("RequestSignedValues Message. Starting Deserialization.");
        let mut cursor = Cursor::new(&msg.data);
        let request = RequestSignedValues::from_bytes(&mut cursor)?;
        debug!("RequestSignedValues Message. Finished Deserialization.");
        if let Some(identifier) = self
            .shared_state
            .quality_to_identifiers
            .lock()
            .await
            .get(&request.quality_string)
        {
            debug!("Found Identifier for {}", &request.quality_string);
            let mut foliage_block_data = None;
            let mut foliage_transaction_block = None;
            if let Some(data) = request.foliage_block_data {
                foliage_block_data = Some(SignatureRequestSourceData {
                    kind: SigningDataKind::FoliageBlockData,
                    data: data.to_bytes(),
                });
            }
            if let Some(data) = request.foliage_transaction_block_data {
                foliage_transaction_block = Some(SignatureRequestSourceData {
                    kind: SigningDataKind::FoliageTransactionBlock,
                    data: data.to_bytes(),
                });
            }
            let request = RequestSignatures {
                plot_identifier: identifier.plot_identifier.clone(),
                challenge_hash: identifier.challenge_hash,
                sp_hash: identifier.sp_hash,
                messages: vec![
                    request.foliage_block_data_hash,
                    request.foliage_transaction_block_hash,
                ],
                message_data: Some(vec![foliage_block_data, foliage_transaction_block]),
                rc_block_unfinished: request.rc_block_unfinished,
            };
            let sig_handle = RespondSignaturesHandler {
                pool_client: self.pool_client.clone(),
                shared_state: self.shared_state.clone(),
                harvester_id: identifier.peer_node_id,
                harvesters: self.harvesters.clone(),
                constants: self.constants,
            };
            if let Some(h) = self.harvesters.get(&identifier.peer_node_id) {
                let harvester = h.clone();
                tokio::spawn(async move {
                    match harvester.as_ref() {
                        Harvesters::DruidGarden(harvester) => {
                            if let Err(e) = harvester.request_signatures(request, sig_handle).await
                            {
                                error!("Error Requesting Signature: {}", e);
                            }
                        }
                    }
                });
            } else {
                error!("Failed to find harvester to send Signatures Request");
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
