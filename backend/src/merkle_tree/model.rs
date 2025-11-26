use std::sync::Arc;

use tokio::sync::RwLock;

use crate::{
    crypto::model::AnonymitySetManager, database::database::Database,
    starknet::relayer::StarknetRelayer,
};

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PoolType {
    Fast,     // < $10K, updates every 30 seconds
    Standard, // >= $10K, updates every 2 minutes or 100 deposits
}

pub struct MerkleTreeManager {
    pub fast_pool_sets: Arc<RwLock<AnonymitySetManager>>,
    pub standard_pool_sets: Arc<RwLock<AnonymitySetManager>>,
    pub fast_relayer: Arc<StarknetRelayer>,
    pub standard_relayer: Arc<StarknetRelayer>,
    pub database: Arc<Database>,
    pub tree_depth: usize,
}
