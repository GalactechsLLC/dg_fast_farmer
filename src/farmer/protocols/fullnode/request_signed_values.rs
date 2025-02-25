use crate::PROTOCOL_VERSION;
use crate::farmer::protocols::harvester::respond_signatures::RespondSignaturesHandler;
use crate::farmer::{FarmerSharedState};
use crate::harvesters::{Harvester};
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
use tokio::sync::RwLock;
use uuid::Uuid;
use dg_xch_clients::websocket::farmer::FarmerClient;
use crate::farmer::config::Config;

pub struct RequestSignedValuesHandle<P, T, H, C> where
    P: PoolClient + Sized + Sync + Send + 'static,
    T: Sync + Send + 'static,
    H: Harvester<T, C> + Sync + Send + 'static,
    C: Send + Sync + 'static,
{
    pub id: Uuid,
    pub shared_state: Arc<FarmerSharedState<T>>,
    pub pool_client: Arc<P>,
    pub harvesters: Arc<HashMap<Bytes32, Arc<H>>>,
    pub constants: &'static ConsensusConstants,
    pub config: Arc<RwLock<Config<C>>>,
    pub client: Arc<RwLock<Option<FarmerClient<T>>>>
}
#[async_trait]
impl<P, T, H, C> MessageHandler for RequestSignedValuesHandle<P, T, H, C> where
    P: PoolClient + Sized + Sync + Send + 'static,
    T: Sync + Send + 'static,
    H: Harvester<T, C> + Sync + Send + 'static,
    C: Send + Sync + 'static
{
    async fn handle(
        &self,
        msg: Arc<ChiaMessage>,
        _peer_id: Arc<Bytes32>,
        _peers: PeerMap,
    ) -> Result<(), Error> {
        debug!("RequestSignedValues Message. Starting Deserialization.");
        let mut cursor = Cursor::new(&msg.data);
        let request = RequestSignedValues::from_bytes(&mut cursor, PROTOCOL_VERSION)?;
        debug!("RequestSignedValues Message. Finished Deserialization.");
        if let Some(identifier) = self
            .shared_state
            .quality_to_identifiers
            .read()
            .await
            .get(&request.quality_string)
        {
            debug!("Found Identifier for {}", &request.quality_string);
            let mut foliage_block_data = None;
            let mut foliage_transaction_block = None;
            if let Some(data) = request.foliage_block_data {
                foliage_block_data = Some(SignatureRequestSourceData {
                    kind: SigningDataKind::FoliageBlockData,
                    data: data.to_bytes(PROTOCOL_VERSION),
                });
            }
            if let Some(data) = request.foliage_transaction_block_data {
                foliage_transaction_block = Some(SignatureRequestSourceData {
                    kind: SigningDataKind::FoliageTransactionBlock,
                    data: data.to_bytes(PROTOCOL_VERSION),
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
                config: self.config.clone(),
                client: self.client.clone(),
            };
            if let Some(h) = self.harvesters.get(&identifier.peer_node_id) {
                let harvester = h.clone();
                tokio::spawn(async move {
                    if let Err(e) = harvester.request_signatures(request, sig_handle).await {
                        error!("Error Requesting Signature: {}", e);
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
