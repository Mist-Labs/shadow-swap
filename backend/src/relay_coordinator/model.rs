use std::{collections::HashMap, sync::Arc};

use tokio::sync::RwLock;

use crate::{database::database::Database, merkle_tree::model::MerkleTreeManager, starknet::relayer::StarknetRelayer, zcash::model::ZcashRelayer};



#[derive(Debug, Clone, Default)]
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

#[derive(Debug, Clone)]
pub struct RetryConfig {
    pub max_attempts: u32,
    pub initial_delay_ms: u64,
    pub max_delay_ms: u64,
    pub backoff_multiplier: f64,
}

#[derive(Debug, Clone)]
pub struct SwapOperationState {
    pub swap_id: String,
    pub operation: String,
    pub attempts: u32,
    pub last_error: Option<String>,
    pub next_retry: Option<chrono::DateTime<chrono::Utc>>,
}

pub struct RelayCoordinator {
    pub starknet_relayer: Arc<StarknetRelayer>,
    pub zcash_relayer: Arc<ZcashRelayer>,
    pub database: Arc<Database>,
    pub metrics: Arc<RwLock<RelayMetrics>>,
    pub merkle_tree_manager: Arc<MerkleTreeManager>,
    pub retry_config: RetryConfig,
    pub operation_states: Arc<RwLock<HashMap<String, SwapOperationState>>>,
    pub start_time: std::time::Instant,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SwapDirection {
    StarknetToZcash,
    ZcashToStarknet,
    Unknown,
}

