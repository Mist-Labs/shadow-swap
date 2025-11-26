use std::sync::Arc;
use tokio::time::{interval, Duration};
use tracing::{error, info, warn};
use anyhow::Result;

use crate::{
    crypto::model::AnonymitySetManager, database::database::Database, merkle_tree::model::{MerkleTreeManager, PoolType}, starknet::relayer::StarknetRelayer
};

impl MerkleTreeManager {
    pub fn new(
        fast_relayer: Arc<StarknetRelayer>,
        standard_relayer: Arc<StarknetRelayer>,
        database: Arc<Database>,
        tree_depth: usize,
    ) -> Self {
        let fast_pool_sets = Arc::new(tokio::sync::RwLock::new(
            AnonymitySetManager::new(tree_depth)
        ));
        
        let standard_pool_sets = Arc::new(tokio::sync::RwLock::new(
            AnonymitySetManager::new(tree_depth)
        ));

        Self {
            fast_pool_sets,
            standard_pool_sets,
            fast_relayer,
            standard_relayer,
            database,
            tree_depth,
        }
    }

    pub async fn start(&self) -> Result<()> {
        info!("🌳 Starting Dual Merkle Tree Manager");
        info!("⚡ Fast Pool: 30 second updates | 🐢 Standard Pool: 2 minute / 100 deposit updates");

        let fast_manager = self.clone_for_fast();
        tokio::spawn(async move {
            if let Err(e) = fast_manager.run_fast_pool().await {
                error!("❌ Fast pool manager error: {}", e);
            }
        });

        let standard_manager = self.clone_for_standard();
        tokio::spawn(async move {
            if let Err(e) = standard_manager.run_standard_pool().await {
                error!("❌ Standard pool manager error: {}", e);
            }
        });

        Ok(())
    }

    async fn run_fast_pool(&self) -> Result<()> {
        let mut update_interval = interval(Duration::from_secs(30));

        loop {
            update_interval.tick().await;

            match self.process_pending_deposits(PoolType::Fast).await {
                Ok(count) if count > 0 => {
                    if let Err(e) = self.update_on_chain_root(PoolType::Fast).await {
                        error!("❌ Fast pool root update error: {}", e);
                    }
                }
                Ok(_) => {}
                Err(e) => {
                    error!("❌ Fast pool deposit processing error: {}", e);
                }
            }
        }
    }

    async fn run_standard_pool(&self) -> Result<()> {
        let mut update_interval = interval(Duration::from_secs(120));
        let mut deposits_since_last_update = 0;

        loop {
            update_interval.tick().await;

            match self.process_pending_deposits(PoolType::Standard).await {
                Ok(count) => {
                    deposits_since_last_update += count;
                }
                Err(e) => {
                    error!("❌ Standard pool deposit processing error: {}", e);
                }
            }

            if deposits_since_last_update >= 100 {
                info!("📊 Standard pool: 100 deposits reached, updating root");
                match self.update_on_chain_root(PoolType::Standard).await {
                    Ok(_) => {
                        deposits_since_last_update = 0;
                    }
                    Err(e) => {
                        error!("❌ Standard pool root update error: {}", e);
                    }
                }
            } else if deposits_since_last_update > 0 {
                if let Err(e) = self.update_on_chain_root(PoolType::Standard).await {
                    error!("❌ Standard pool root update error: {}", e);
                }
            }
        }
    }

    async fn process_pending_deposits(&self, pool_type: PoolType) -> Result<usize> {
        let pending_deposits = self.database.get_pending_merkle_deposits(pool_type)
            .map_err(|e| anyhow::anyhow!("Failed to get pending deposits: {}", e))?;

        if pending_deposits.is_empty() {
            return Ok(0);
        }

        let pool_name = match pool_type {
            PoolType::Fast => "Fast",
            PoolType::Standard => "Standard",
        };

        info!(
            "🌳 {} Pool: Processing {} pending deposits",
            pool_name,
            pending_deposits.len()
        );

        let mut sets = match pool_type {
            PoolType::Fast => self.fast_pool_sets.write().await,
            PoolType::Standard => self.standard_pool_sets.write().await,
        };

        let mut count = 0;
        for deposit in &pending_deposits {
            let tree = sets.get_or_create_tree(&deposit.token_address);

            match tree.add_commitment(&deposit.commitment) {
                Ok(index) => {
                    info!(
                        "✅ {} Pool: Added commitment {} (index: {})",
                        pool_name, deposit.commitment, index
                    );

                    self.database.mark_deposit_in_merkle_tree(
                        &deposit.commitment,
                        index as u32,
                        pool_type,
                    ).map_err(|e| anyhow::anyhow!("Failed to mark deposit: {}", e))?;
                    count += 1;
                }
                Err(e) => {
                    warn!("⚠️ Failed to add commitment {}: {}", deposit.commitment, e);
                }
            }
        }

        Ok(count)
    }

    async fn update_on_chain_root(&self, pool_type: PoolType) -> Result<()> {
        let (sets, relayer, pool_name) = match pool_type {
            PoolType::Fast => (
                self.fast_pool_sets.read().await,
                &self.fast_relayer,
                "Fast",
            ),
            PoolType::Standard => (
                self.standard_pool_sets.read().await,
                &self.standard_relayer,
                "Standard",
            ),
        };

        let current_on_chain_root = relayer.get_current_root(pool_type).await
            .map_err(|e| anyhow::anyhow!("Failed to get current root: {}", e))?;

        for (token_address, tree) in sets.trees.iter() {
            let local_root = tree.get_root();

            if local_root != current_on_chain_root && !local_root.is_empty() {
                info!(
                    "📊 {} Pool: Root changed for token {}, updating on-chain: {} -> {}",
                    pool_name, token_address, current_on_chain_root, local_root
                );

                match relayer.update_merkle_root(local_root, pool_type).await {
                    Ok(tx_hash) => {
                        info!(
                            "✅ {} Pool: Merkle root updated on-chain: {}",
                            pool_name, tx_hash
                        );
                        self.database
                            .record_merkle_root_update(local_root, &tx_hash, pool_type)
                            .map_err(|e| anyhow::anyhow!("Failed to record root update: {}", e))?;
                        return Ok(());
                    }
                    Err(e) => {
                        error!("❌ {} Pool: Failed to update root on-chain: {}", pool_name, e);
                    }
                }
            }
        }

        Ok(())
    }

    pub async fn generate_proof(
        &self,
        token: &str,
        commitment: &str,
        pool_type: PoolType,
    ) -> Result<crate::crypto::model::MembershipProof> {
        let sets = match pool_type {
            PoolType::Fast => self.fast_pool_sets.read().await,
            PoolType::Standard => self.standard_pool_sets.read().await,
        };

        sets.generate_proof(token, commitment)
            .map_err(|e| anyhow::anyhow!("Failed to generate proof: {}", e))
    }

    pub async fn get_root(&self, token: &str, pool_type: PoolType) -> Option<String> {
        let sets = match pool_type {
            PoolType::Fast => self.fast_pool_sets.read().await,
            PoolType::Standard => self.standard_pool_sets.read().await,
        };
        sets.get_root(token)
    }

    pub async fn get_set_size(&self, token: &str, pool_type: PoolType) -> usize {
        let sets = match pool_type {
            PoolType::Fast => self.fast_pool_sets.read().await,
            PoolType::Standard => self.standard_pool_sets.read().await,
        };
        sets.get_set_size(token)
    }

    fn clone_for_fast(&self) -> Self {
        Self {
            fast_pool_sets: Arc::clone(&self.fast_pool_sets),
            standard_pool_sets: Arc::clone(&self.standard_pool_sets),
            fast_relayer: Arc::clone(&self.fast_relayer),
            standard_relayer: Arc::clone(&self.standard_relayer),
            database: Arc::clone(&self.database),
            tree_depth: self.tree_depth,
        }
    }

    fn clone_for_standard(&self) -> Self {
        Self {
            fast_pool_sets: Arc::clone(&self.fast_pool_sets),
            standard_pool_sets: Arc::clone(&self.standard_pool_sets),
            fast_relayer: Arc::clone(&self.fast_relayer),
            standard_relayer: Arc::clone(&self.standard_relayer),
            database: Arc::clone(&self.database),
            tree_depth: self.tree_depth,
        }
    }
}