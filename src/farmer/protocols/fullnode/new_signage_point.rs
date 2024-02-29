use crate::farmer::protocols::harvester::new_proof_of_space::NewProofOfSpaceHandle;
use crate::farmer::{ExtendedFarmerSharedState, FarmerSharedState};
use crate::harvesters::{Harvester, Harvesters};
use async_trait::async_trait;
use dg_xch_clients::api::pool::PoolClient;
use dg_xch_core::blockchain::proof_of_space::calculate_prefix_bits;
use dg_xch_core::blockchain::sized_bytes::Bytes32;
use dg_xch_core::consensus::constants::ConsensusConstants;
use dg_xch_core::consensus::pot_iterations::POOL_SUB_SLOT_ITERS;
use dg_xch_core::protocols::farmer::{FarmerPoolState, NewSignagePoint};
use dg_xch_core::protocols::harvester::{NewSignagePointHarvester, PoolDifficulty};
use dg_xch_core::protocols::{ChiaMessage, MessageHandler, PeerMap};
use dg_xch_serialize::ChiaSerialize;
use log::{debug, error, info, warn};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::io::{Cursor, Error};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;
use uuid::Uuid;

pub struct NewSignagePointHandle<T: PoolClient + Sized + Sync + Send + 'static> {
    pub id: Uuid,
    pub harvester_id: Bytes32,
    pub pool_state: Arc<Mutex<HashMap<Bytes32, FarmerPoolState>>>,
    pub pool_client: Arc<T>,
    pub signage_points: Arc<Mutex<HashMap<Bytes32, Vec<NewSignagePoint>>>>,
    pub cache_time: Arc<Mutex<HashMap<Bytes32, Instant>>>,
    pub shared_state: Arc<FarmerSharedState<ExtendedFarmerSharedState>>,
    pub harvesters: Arc<HashMap<Bytes32, Arc<Harvesters>>>,
    pub constants: &'static ConsensusConstants,
}
#[async_trait]
impl<T: PoolClient + Sized + Sync + Send + 'static> MessageHandler for NewSignagePointHandle<T> {
    async fn handle(
        &self,
        msg: Arc<ChiaMessage>,
        _peer_id: Arc<Bytes32>,
        _peers: PeerMap,
    ) -> Result<(), Error> {
        debug!("NewSignagePoint Message. Starting Deserialization.");
        let mut cursor = Cursor::new(&msg.data);
        let sp = NewSignagePoint::from_bytes(&mut cursor)?;
        debug!("NewSignagePoint Message. Finished Deserialization.");
        if sp.sp_source_data.is_none() {
            error!("No SignagePoint Source Data Included for Farmer which Requires it");
        }
        let mut pool_difficulties = vec![];
        debug!("Generating Pool Difficulties");
        for (p2_singleton_puzzle_hash, pool_dict) in self.pool_state.lock().await.iter() {
            if let Some(config) = &pool_dict.pool_config {
                if config.pool_url.is_empty() {
                    debug!("Self Pooling Detected for {p2_singleton_puzzle_hash}");
                    continue;
                } else if let Some(difficulty) = pool_dict.current_difficulty {
                    debug!("Using Difficulty {difficulty} for p2_singleton_puzzle_hash: {p2_singleton_puzzle_hash}");
                    pool_difficulties.push(PoolDifficulty {
                        difficulty,
                        sub_slot_iters: POOL_SUB_SLOT_ITERS,
                        pool_contract_puzzle_hash: *p2_singleton_puzzle_hash,
                    })
                } else {
                    warn!("No pool specific difficulty has been set for {p2_singleton_puzzle_hash}, check communication with the pool, skipping this signage point, pool: {}", &config.pool_url);
                    continue;
                }
            }
        }
        info!(
            "New Signage Point({}): {:?}",
            sp.signage_point_index, sp.challenge_hash
        );
        *self.shared_state.data.last_sp_timestamp.lock().await = Instant::now();
        let filter_prefix_bits = calculate_prefix_bits(self.constants, sp.peak_height);
        let sp_hash = sp.challenge_chain_sp;
        let harvester_point = Arc::new(NewSignagePointHarvester {
            challenge_hash: sp.challenge_hash,
            difficulty: sp.difficulty,
            sub_slot_iters: sp.sub_slot_iters,
            signage_point_index: sp.signage_point_index,
            sp_hash,
            pool_difficulties,
            filter_prefix_bits,
        });
        self.cache_time.lock().await.insert(sp_hash, Instant::now());
        self.shared_state.data.gui_stats.lock().await.most_recent_sp =
            (sp.challenge_hash, sp.signage_point_index);
        match self.signage_points.lock().await.entry(sp_hash) {
            Entry::Occupied(mut e) => {
                e.get_mut().push(sp);
            }
            Entry::Vacant(e) => {
                e.insert(vec![sp]);
            }
        }
        debug!("Sending NewSignagePoint to Harvesters, Using Filter Bits: {filter_prefix_bits}");
        for (_, harvester) in self.harvesters.iter() {
            let harvester_point = harvester_point.clone();
            let harvesters = self.harvesters.clone();
            let pool_client = self.pool_client.clone();
            let shared_state = self.shared_state.clone();
            let constants = self.constants;
            let harvester = harvester.clone();
            tokio::spawn(async move {
                match harvester.as_ref() {
                    Harvesters::DruidGarden(harvester) => {
                        let proof_handle = NewProofOfSpaceHandle {
                            pool_client,
                            shared_state,
                            harvester_id: harvester.uuid,
                            harvesters,
                            constants,
                        };
                        if let Err(e) = harvester
                            .new_signage_point(harvester_point, proof_handle)
                            .await
                        {
                            error!("Error Handling Signage Point: {}", e);
                        }
                    }
                }
            });
        }
        debug!("Finished Processing SignagePoint: {sp_hash}");
        Ok(())
    }
}
