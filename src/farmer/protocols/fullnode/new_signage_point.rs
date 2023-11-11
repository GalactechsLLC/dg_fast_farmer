use crate::farmer::protocols::harvester::new_proof_of_space::NewProofOfSpaceHandle;
use crate::farmer::FarmerSharedState;
use crate::harvesters::{Harvester, Harvesters};
use crate::tasks::pool_state_updater::FarmerPoolState;
use async_trait::async_trait;
use dg_xch_clients::api::pool::PoolClient;
use dg_xch_clients::protocols::farmer::NewSignagePoint;
use dg_xch_clients::protocols::harvester::{NewSignagePointHarvester, PoolDifficulty};
use dg_xch_clients::websocket::{ChiaMessage, MessageHandler};
use dg_xch_core::blockchain::sized_bytes::Bytes32;
use dg_xch_core::consensus::constants::ConsensusConstants;
use dg_xch_core::consensus::pot_iterations::POOL_SUB_SLOT_ITERS;
use dg_xch_serialize::ChiaSerialize;
use log::{debug, info, warn};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::io::{Cursor, Error};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::Mutex;
use uuid::Uuid;

pub struct NewSignagePointHandle<T: PoolClient + Sized + Sync + Send + 'static> {
    pub id: Uuid,
    pub pool_state: Arc<Mutex<HashMap<Bytes32, FarmerPoolState>>>,
    pub pool_client: Arc<T>,
    pub signage_points: Arc<Mutex<HashMap<Bytes32, Vec<NewSignagePoint>>>>,
    pub cache_time: Arc<Mutex<HashMap<Bytes32, Instant>>>,
    pub shared_state: Arc<FarmerSharedState>,
    pub harvesters: Arc<HashMap<Uuid, Arc<Harvesters>>>,
    pub constants: &'static ConsensusConstants,
}
#[async_trait]
impl<T: PoolClient + Sized + Sync + Send + 'static> MessageHandler for NewSignagePointHandle<T> {
    async fn handle(&self, msg: Arc<ChiaMessage>) -> Result<(), Error> {
        let mut cursor = Cursor::new(&msg.data);
        let sp = NewSignagePoint::from_bytes(&mut cursor)?;
        let mut pool_difficulties = vec![];
        for (p2_singleton_puzzle_hash, pool_dict) in self.pool_state.lock().await.iter() {
            if let Some(config) = &pool_dict.pool_config {
                if config.pool_url.is_empty() {
                    //Self Pooling
                    continue;
                } else if let Some(difficulty) = pool_dict.current_difficulty {
                    debug!("Setting Difficulty for pool: {}", difficulty);
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
        let harvester_point = Arc::new(NewSignagePointHarvester {
            challenge_hash: sp.challenge_hash,
            difficulty: sp.difficulty,
            sub_slot_iters: sp.sub_slot_iters,
            signage_point_index: sp.signage_point_index,
            sp_hash: sp.challenge_chain_sp,
            pool_difficulties,
        });
        self.cache_time
            .lock()
            .await
            .insert(sp.challenge_chain_sp, Instant::now());
        self.shared_state.gui_stats.lock().await.most_recent_sp =
            (sp.challenge_hash, sp.signage_point_index);
        match self
            .signage_points
            .lock()
            .await
            .entry(sp.challenge_chain_sp)
        {
            Entry::Occupied(mut e) => {
                e.get_mut().push(sp);
            }
            Entry::Vacant(e) => {
                e.insert(vec![sp]);
            }
        }
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
                            harvester_id: harvester.uuid(),
                            harvesters,
                            constants,
                        };
                        harvester
                            .new_signage_point(harvester_point, proof_handle)
                            .await?;
                    }
                }
                Ok::<(), Error>(())
            });
        }
        Ok(())
    }
}
