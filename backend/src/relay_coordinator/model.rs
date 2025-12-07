use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::{
    database::database::Database, merkle_tree::model::MerkleTreeManager,
    pricefeed::pricefeed::PriceCache, starknet::relayer::StarknetRelayer,
    zcash::model::ZcashRelayer,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayMetrics {
    pub total_swaps_processed: u64,
    pub successful_swaps: u64,
    pub failed_swaps: u64,
    pub refunded_swaps: u64,
    pub starknet_htlcs_created: u64,
    pub zcash_htlcs_created: u64,
    pub starknet_redemptions: u64,
    pub zcash_redemptions: u64,
    pub retry_attempts: u64,
    pub last_error: Option<String>,
    pub uptime_seconds: u64,
}

impl Default for RelayMetrics {
    fn default() -> Self {
        Self {
            total_swaps_processed: 0,
            successful_swaps: 0,
            failed_swaps: 0,
            refunded_swaps: 0,
            starknet_htlcs_created: 0,
            zcash_htlcs_created: 0,
            starknet_redemptions: 0,
            zcash_redemptions: 0,
            retry_attempts: 0,
            last_error: None,
            uptime_seconds: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub max_attempts: u32,
    pub initial_delay_ms: u64,
    pub max_delay_ms: u64,
    pub backoff_multiplier: f64,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SwapDirection {
    StarknetToZcash,
    ZcashToStarknet,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapOperationState {
    pub swap_id: String,
    pub current_step: String,
    pub attempts: u32,
    pub last_error: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

pub struct RelayCoordinator {
    pub starknet_relayer: Arc<StarknetRelayer>,
    pub zcash_relayer: Arc<ZcashRelayer>,
    pub database: Arc<Database>,
    pub merkle_tree_manager: Arc<MerkleTreeManager>,
    pub price_cache: Arc<PriceCache>,
    pub metrics: Arc<RwLock<RelayMetrics>>,
    pub retry_config: RetryConfig,
    pub operation_states: Arc<RwLock<HashMap<String, SwapOperationState>>>,
    pub start_time: tokio::time::Instant,
}
