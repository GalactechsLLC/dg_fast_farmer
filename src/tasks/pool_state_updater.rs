use crate::farmer::config::{Config, PoolWalletConfig};
use crate::farmer::FarmerSharedState;
use crate::HEADERS;
use blst::min_pk::SecretKey;
use dg_xch_clients::api::pool::{DefaultPoolClient, PoolClient};
use dg_xch_clients::protocols::pool::{
    get_current_authentication_token, AuthenticationPayload, GetFarmerRequest, GetFarmerResponse,
    PoolError, PoolErrorCode, PostFarmerPayload, PostFarmerRequest, PostFarmerResponse,
    PutFarmerPayload, PutFarmerRequest, PutFarmerResponse,
};
use dg_xch_core::blockchain::sized_bytes::{hex_to_bytes, Bytes32, Bytes48};
use dg_xch_core::clvm::bls_bindings::{sign, verify_signature};
use dg_xch_keys::decode_puzzle_hash;
use dg_xch_serialize::{hash_256, ChiaSerialize};
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::io::Error;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::Mutex;

const UPDATE_POOL_INFO_INTERVAL: u64 = 600;
const UPDATE_POOL_INFO_FAILURE_RETRY_INTERVAL: u64 = 120;
const UPDATE_POOL_FARMER_INFO_INTERVAL: u64 = 300;

#[derive(Debug, Clone)]
pub struct FarmerPoolState {
    pub(crate) next_farmer_update: Instant,
    pub(crate) next_pool_info_update: Instant,
    pub(crate) current_points: u64,
    pub(crate) current_difficulty: Option<u64>,
    pub(crate) pool_config: Option<PoolWalletConfig>,
    pub(crate) authentication_token_timeout: Option<u8>,
}
impl Default for FarmerPoolState {
    fn default() -> Self {
        Self {
            next_farmer_update: Instant::now(),
            next_pool_info_update: Instant::now(),
            current_points: 0,
            current_difficulty: None,
            pool_config: None,
            authentication_token_timeout: None,
        }
    }
}

pub async fn pool_updater(shared_state: Arc<FarmerSharedState>) {
    let mut last_update = Instant::now();
    let mut first = true;
    let pool_client = Arc::new(DefaultPoolClient::new());
    loop {
        if !shared_state.run.load(Ordering::Relaxed) {
            break;
        } else if first
            || shared_state.force_pool_update.load(Ordering::Relaxed)
            || Instant::now().duration_since(last_update).as_secs() >= 60
        {
            info!("Updating Pool State");
            update_pool_state(
                shared_state.auth_secret_keys.as_ref(),
                shared_state.owner_secret_keys.as_ref(),
                shared_state.pool_states.clone(),
                pool_client.clone(),
                shared_state.config.clone(),
            )
            .await;
            first = false;
            last_update = Instant::now();
            shared_state.gui_stats.lock().await.last_pool_update = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("System Time should be Greater than Epoch")
                .as_secs();
            shared_state
                .force_pool_update
                .store(false, Ordering::Relaxed);
        } else {
            tokio::time::sleep(Duration::from_secs(1)).await
        }
    }
    info!("Pool Handle Stopped");
}

pub async fn get_farmer<T: PoolClient + Sized + Sync + Send>(
    pool_config: &PoolWalletConfig,
    authentication_token_timeout: u8,
    authentication_sk: &SecretKey,
    client: Arc<T>,
) -> Result<GetFarmerResponse, PoolError> {
    let authentication_token = get_current_authentication_token(authentication_token_timeout);
    let msg = AuthenticationPayload {
        method_name: "get_farmer".to_string(),
        launcher_id: pool_config.launcher_id,
        target_puzzle_hash: pool_config.target_puzzle_hash,
        authentication_token,
    }
    .to_bytes();
    let to_sign = hash_256(&msg);
    let signature = sign(authentication_sk, &to_sign);
    if !verify_signature(&authentication_sk.sk_to_pk(), &to_sign, &signature) {
        error!("Farmer GET Failed to Validate Signature");
        return Err(PoolError {
            error_code: PoolErrorCode::InvalidSignature as u8,
            error_message: "Local Failed to Validate Signature".to_string(),
        });
    }
    client
        .get_farmer(
            &pool_config.pool_url,
            GetFarmerRequest {
                launcher_id: pool_config.launcher_id,
                authentication_token,
                signature: signature.to_bytes().into(),
            },
            &Some(HEADERS.clone()),
        )
        .await
}

async fn do_auth(
    pool_config: &PoolWalletConfig,
    owner_sk: &SecretKey,
    auth_keys: &HashMap<Bytes48, SecretKey>,
) -> Result<Bytes48, PoolError> {
    if owner_sk.sk_to_pk().to_bytes() != *pool_config.owner_public_key.to_sized_bytes() {
        Err(PoolError {
            error_code: PoolErrorCode::ServerException as u8,
            error_message: "Owner Keys Mismatch".to_string(),
        })
    } else if let Some(auth_key) = auth_keys.get(&owner_sk.sk_to_pk().to_bytes().into()) {
        Ok(auth_key.sk_to_pk().to_bytes().into())
    } else {
        Err(PoolError {
            error_code: PoolErrorCode::NotFound as u8,
            error_message: "Auth Key Not Found".to_string(),
        })
    }
}

pub async fn post_farmer<T: PoolClient + Sized + Sync + Send>(
    pool_config: &PoolWalletConfig,
    payout_instructions: &str,
    authentication_token_timeout: u8,
    owner_sk: &SecretKey,
    auth_keys: &HashMap<Bytes48, SecretKey>,
    suggested_difficulty: Option<u64>,
    client: Arc<T>,
) -> Result<PostFarmerResponse, PoolError> {
    let payload = PostFarmerPayload {
        launcher_id: pool_config.launcher_id,
        authentication_token: get_current_authentication_token(authentication_token_timeout),
        authentication_public_key: do_auth(pool_config, owner_sk, auth_keys).await?,
        payout_instructions: parse_payout_address(payout_instructions.to_string()).map_err(
            |e| PoolError {
                error_code: PoolErrorCode::InvalidPayoutInstructions as u8,
                error_message: format!(
                    "Failed to Parse Payout Instructions: {}, {:?}",
                    payout_instructions, e
                ),
            },
        )?,
        suggested_difficulty,
    };
    let to_sign = hash_256(payload.to_bytes());
    let signature = sign(owner_sk, &to_sign);
    if !verify_signature(&owner_sk.sk_to_pk(), &to_sign, &signature) {
        error!("Farmer POST Failed to Validate Signature");
        return Err(PoolError {
            error_code: PoolErrorCode::InvalidSignature as u8,
            error_message: "Local Failed to Validate Signature".to_string(),
        });
    }
    client
        .post_farmer(
            &pool_config.pool_url,
            PostFarmerRequest {
                payload,
                signature: signature.to_bytes().into(),
            },
            &Some(HEADERS.clone()),
        )
        .await
}

pub async fn put_farmer<T: PoolClient + Sized + Sync + Send>(
    pool_config: &PoolWalletConfig,
    payout_instructions: &str,
    authentication_token_timeout: u8,
    owner_sk: &SecretKey,
    auth_keys: &HashMap<Bytes48, SecretKey>,
    suggested_difficulty: Option<u64>,
    client: Arc<T>,
) -> Result<PutFarmerResponse, PoolError> {
    let authentication_public_key = do_auth(pool_config, owner_sk, auth_keys).await?;
    let payload = PutFarmerPayload {
        launcher_id: pool_config.launcher_id,
        authentication_token: get_current_authentication_token(authentication_token_timeout),
        authentication_public_key: Some(authentication_public_key),
        payout_instructions: parse_payout_address(payout_instructions.to_string()).ok(),
        suggested_difficulty,
    };
    let to_sign = hash_256(payload.to_bytes());
    let signature = sign(owner_sk, &to_sign);
    if !verify_signature(&owner_sk.sk_to_pk(), &to_sign, &signature) {
        error!("Local Failed to Validate Signature");
        return Err(PoolError {
            error_code: PoolErrorCode::InvalidSignature as u8,
            error_message: "Local Failed to Validate Signature".to_string(),
        });
    }
    let request = PutFarmerRequest {
        payload,
        signature: signature.to_bytes().into(),
    };
    client
        .put_farmer(&pool_config.pool_url, request, &Some(HEADERS.clone()))
        .await
}

pub async fn update_pool_farmer_info<T: PoolClient + Sized + Sync + Send>(
    pool_state: &mut FarmerPoolState,
    pool_config: &PoolWalletConfig,
    authentication_token_timeout: u8,
    authentication_sk: &SecretKey,
    client: Arc<T>,
) -> Result<GetFarmerResponse, PoolError> {
    let response = get_farmer(
        pool_config,
        authentication_token_timeout,
        authentication_sk,
        client,
    )
    .await?;
    pool_state.current_difficulty = Some(response.current_difficulty);
    pool_state.current_points = response.current_points;
    info!(
        "Updating Pool Difficulty: {:?} ",
        pool_state.current_difficulty
    );
    info!("Updating Current Points: {:?} ", pool_state.current_points);
    Ok(response)
}

pub async fn update_pool_state<'a, T: 'a + PoolClient + Sized + Sync + Send>(
    auth_keys: &HashMap<Bytes48, SecretKey>,
    owner_keys: &HashMap<Bytes48, SecretKey>,
    pool_states: Arc<Mutex<HashMap<Bytes32, FarmerPoolState>>>,
    client: Arc<T>,
    config: Arc<Config>,
) {
    for pool_config in &config.pool_info {
        if let (Some(owner_secret_key), Some(auth_secret_key)) = (
            owner_keys.get(&pool_config.owner_public_key),
            auth_keys.get(&pool_config.owner_public_key),
        ) {
            let state_exists = pool_states
                .lock()
                .await
                .get(&pool_config.p2_singleton_puzzle_hash)
                .is_some();
            if !state_exists {
                pool_states.lock().await.insert(
                    pool_config.p2_singleton_puzzle_hash,
                    FarmerPoolState {
                        next_farmer_update: Instant::now(),
                        next_pool_info_update: Instant::now(),
                        current_points: 0,
                        current_difficulty: None,
                        pool_config: None,
                        authentication_token_timeout: None,
                    },
                );
                info!("Added pool: {:?}", pool_config);
            }
            let mut pool_state = pool_states
                .lock()
                .await
                .get_mut(&pool_config.p2_singleton_puzzle_hash)
                .cloned()
                .unwrap_or_default();
            pool_state.pool_config = Some(pool_config.clone());
            if pool_config.pool_url.is_empty() {
                continue;
            }
            if config.selected_network == "mainnet" && !pool_config.pool_url.starts_with("https") {
                error!(
                    "Pool URLs must be HTTPS on mainnet {}",
                    pool_config.pool_url
                );
                continue;
            }
            if Instant::now() >= pool_state.next_pool_info_update {
                pool_state.next_pool_info_update =
                    Instant::now() + Duration::from_secs(UPDATE_POOL_INFO_INTERVAL);
                //Makes a GET request to the pool to get the updated information
                match client.get_pool_info(&pool_config.pool_url).await {
                    Ok(pool_info) => {
                        pool_state.authentication_token_timeout =
                            Some(pool_info.authentication_token_timeout);
                        // Only update the first time from GET /pool_info, gets updated from GET /farmer later
                        if pool_state.current_difficulty.is_none() {
                            pool_state.current_difficulty = Some(pool_info.minimum_difficulty);
                        }
                    }
                    Err(e) => {
                        pool_state.next_pool_info_update = Instant::now()
                            + Duration::from_secs(UPDATE_POOL_INFO_FAILURE_RETRY_INTERVAL);
                        error!("Update Pool Info Error: {:?}", e);
                    }
                }
            } else {
                debug!("Not Ready for Update");
            }
            if Instant::now() >= pool_state.next_farmer_update {
                pool_state.next_farmer_update =
                    Instant::now() + Duration::from_secs(UPDATE_POOL_FARMER_INFO_INTERVAL);
                if let Some(authentication_token_timeout) = pool_state.authentication_token_timeout
                {
                    info!("Running Farmer Pool Update");
                    let farmer_info = match update_pool_farmer_info(
                        &mut pool_state,
                        pool_config,
                        authentication_token_timeout,
                        auth_secret_key,
                        client.clone(),
                    )
                    .await
                    {
                        Ok(resp) => Some(resp),
                        Err(e) => {
                            if e.error_code == PoolErrorCode::FarmerNotKnown as u8 {
                                warn!("Farmer Pool Not Known");
                                match post_farmer(
                                    pool_config,
                                    &config.payout_address,
                                    authentication_token_timeout,
                                    owner_secret_key,
                                    auth_keys,
                                    pool_config.difficulty,
                                    client.clone(),
                                )
                                .await
                                {
                                    Ok(resp) => {
                                        info!(
                                            "Welcome message from {} : {}",
                                            pool_config.pool_url, resp.welcome_message
                                        );
                                    }
                                    Err(e) => {
                                        error!("Failed post farmer info. {:?}", e);
                                    }
                                }
                                match update_pool_farmer_info(
                                    &mut pool_state,
                                    pool_config,
                                    authentication_token_timeout,
                                    auth_secret_key,
                                    client.clone(),
                                )
                                .await
                                {
                                    Ok(resp) => Some(resp),
                                    Err(e) => {
                                        error!(
                                            "Failed to update farmer info after POST /farmer. {:?}",
                                            e
                                        );
                                        None
                                    }
                                }
                            } else if e.error_code == PoolErrorCode::InvalidSignature as u8 {
                                warn!("Invalid Signature Detected, Updating Farmer Auth Key");
                                match put_farmer(
                                    pool_config,
                                    &config.payout_address,
                                    authentication_token_timeout,
                                    owner_secret_key,
                                    auth_keys,
                                    pool_config.difficulty,
                                    client.clone(),
                                )
                                .await
                                {
                                    Ok(res) => {
                                        info!("Farmer Update Response: {:?}", res);
                                        update_pool_farmer_info(
                                            &mut pool_state,
                                            pool_config,
                                            authentication_token_timeout,
                                            auth_secret_key,
                                            client.clone(),
                                        )
                                        .await
                                        .ok()
                                    }
                                    Err(e) => {
                                        error!("Failed to update farmer auth key. {:?}", e);
                                        None
                                    }
                                }
                            } else {
                                None
                            }
                        }
                    };
                    let old_instructions;
                    let payout_instructions_update_required = if let Some(info) = farmer_info {
                        if let (Ok(p1), Ok(p2)) = (
                            parse_payout_address(config.payout_address.to_ascii_lowercase()),
                            parse_payout_address(info.payout_instructions.to_ascii_lowercase()),
                        ) {
                            old_instructions = p2;
                            p1 != old_instructions
                        } else {
                            old_instructions = String::new();
                            false
                        }
                    } else {
                        old_instructions = String::new();
                        false
                    };
                    let difficulty_update_required = pool_config.difficulty.unwrap_or_default() > 0
                        && pool_state.current_difficulty < pool_config.difficulty;
                    if payout_instructions_update_required || difficulty_update_required {
                        if payout_instructions_update_required {
                            info!(
                                "Updating Payout Address from {} to {}",
                                config.payout_address.to_ascii_lowercase(),
                                old_instructions
                            );
                        }
                        if difficulty_update_required {
                            info!(
                                "Updating Difficulty from {} to {}",
                                pool_state.current_difficulty.unwrap_or_default(),
                                pool_config.difficulty.unwrap_or_default()
                            );
                        }
                        match owner_keys.get(&pool_config.owner_public_key) {
                            None => {
                                error!(
                                    "Could not find Owner SK for {}",
                                    &pool_config.owner_public_key
                                );
                                continue;
                            }
                            Some(sk) => {
                                match put_farmer(
                                    pool_config,
                                    &config.payout_address,
                                    authentication_token_timeout,
                                    sk,
                                    auth_keys,
                                    pool_config.difficulty,
                                    client.clone(),
                                )
                                .await
                                {
                                    Ok(res) => {
                                        if res.suggested_difficulty.is_some() {
                                            pool_state.current_difficulty = pool_config.difficulty
                                        }
                                        info!("Farmer Update Response: {:?}", res);
                                    }
                                    Err(e) => {
                                        error!("Failed to update farmer auth key. {:?}", e);
                                    }
                                }
                            }
                        }
                    }
                } else {
                    warn!("No pool specific authentication_token_timeout has been set for {}, check communication with the pool.", &pool_config.p2_singleton_puzzle_hash);
                }
                //Update map
                pool_states
                    .lock()
                    .await
                    .insert(pool_config.p2_singleton_puzzle_hash, pool_state);
            }
        } else {
            warn!(
                "Could not find owner sk for: {:?}",
                &pool_config.owner_public_key
            );
        }
    }
}

fn parse_payout_address(s: String) -> Result<String, Error> {
    Ok(if s.starts_with("xch") || s.starts_with("txch") {
        hex::encode(decode_puzzle_hash(&s)?)
    } else if s.len() == 64 {
        match hex_to_bytes(&s) {
            Ok(h) => hex::encode(h),
            Err(_) => s,
        }
    } else {
        s
    })
}
