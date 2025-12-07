use anyhow::Result;
use std::sync::Arc;
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, warn};

use crate::{
    crypto::model::AnonymitySetManager,
    database::database::Database,
    merkle_tree::model::{MerkleTreeManager, PoolType},
    starknet::relayer::StarknetRelayer,
};

impl MerkleTreeManager {
    pub fn new(
        fast_relayer: Arc<StarknetRelayer>,
        standard_relayer: Arc<StarknetRelayer>,
        database: Arc<Database>,
        tree_depth: usize,
    ) -> Self {
        let fast_pool_sets = Arc::new(tokio::sync::RwLock::new(AnonymitySetManager::new(
            tree_depth,
        )));

        let standard_pool_sets = Arc::new(tokio::sync::RwLock::new(AnonymitySetManager::new(
            tree_depth,
        )));

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
        info!("🌳 Merkle Tree Manager starting up");
        info!("🔍 Checking for pending deposits from previous session...");

        match self.process_pending_deposits(PoolType::Fast).await {
            Ok(count) if count > 0 => {
                info!("✅ Recovered {} pending Fast pool deposits", count);
            }
            Ok(_) => info!("✅ No pending Fast pool deposits"),
            Err(e) => error!("❌ Failed to process pending Fast deposits: {}", e),
        }

        match self.process_pending_deposits(PoolType::Standard).await {
            Ok(count) if count > 0 => {
                info!("✅ Recovered {} pending Standard pool deposits", count);
            }
            Ok(_) => info!("✅ No pending Standard pool deposits"),
            Err(e) => error!("❌ Failed to process pending Standard deposits: {}", e),
        }
        info!("🌳 Starting Dual Merkle Tree Manager");
        info!("⚡ Fast Pool: 30 second updates | 🐢 Standard Pool: 2 minute / 100 deposit updates");

        tokio::try_join!(self.run_fast_pool(), self.run_standard_pool())?;

        Ok(())
    }

    pub async fn add_commitment_immediately(
        &self,
        commitment: &str,
        token: &str,
        pool_type: PoolType,
    ) -> Result<usize> {
        let mut sets = match pool_type {
            PoolType::Fast => self.fast_pool_sets.write().await,
            PoolType::Standard => self.standard_pool_sets.write().await,
        };
            
        let tree = sets.get_or_create_tree(token);

        let index = tree.add_commitment(commitment)?;

        info!(
            "✅ Commitment added at index {} for {:?} pool, token: {}",
            index, pool_type, token
        );

        Ok(index)
    }

    async fn run_fast_pool(&self) -> Result<()> {
        let mut update_interval = interval(Duration::from_secs(15));

        loop {
            update_interval.tick().await;

            let pending_count = self
                .database
                .get_pending_commitment_count(PoolType::Fast)
                .unwrap_or(0);

            if pending_count >= 5 {
                if let Err(e) = self.update_on_chain_root(PoolType::Fast).await {
                    error!("❌ Fast pool root update failed: {}", e);
                }
            }
        }
    }

    async fn run_standard_pool(&self) -> Result<()> {
        let mut update_interval = interval(Duration::from_secs(120));

        loop {
            update_interval.tick().await;

            let pending_count = self
                .database
                .get_pending_commitment_count(PoolType::Standard)
                .unwrap_or(0);

            if pending_count >= 100 {
                if let Err(e) = self.update_on_chain_root(PoolType::Standard).await {
                    error!("❌ Standard pool root update failed: {}", e);
                }
            }
        }
    }

    async fn process_pending_deposits(&self, pool_type: PoolType) -> Result<usize> {
        let pending_deposits = self
            .database
            .get_pending_merkle_deposits(pool_type)
            .map_err(|e| anyhow::anyhow!("Failed to get pending deposits: {}", e))?;

        if pending_deposits.is_empty() {
            debug!("No pending deposits for {:?} pool", pool_type);
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

                    self.database
                        .mark_deposit_in_merkle_tree(&deposit.commitment, index as u32, pool_type)
                        .map_err(|e| anyhow::anyhow!("Failed to mark deposit: {}", e))?;
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
            PoolType::Fast => (self.fast_pool_sets.read().await, &self.fast_relayer, "Fast"),
            PoolType::Standard => (
                self.standard_pool_sets.read().await,
                &self.standard_relayer,
                "Standard",
            ),
        };

        // ✅ Handle case where relayer RPC might fail
        let current_on_chain_root = match relayer.get_current_root(pool_type).await {
            Ok(root) => root,
            Err(e) => {
                warn!(
                    "⚠️ {} Pool: Failed to get current root (will retry): {}",
                    pool_name, e
                );
                return Err(anyhow::anyhow!("Failed to get current root: {}", e));
            }
        };

        // ✅ Handle case where there are no trees yet
        if sets.trees.is_empty() {
            debug!("{} Pool: No merkle trees initialized yet", pool_name);
            return Ok(());
        }

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
                        warn!(
                            "⚠️ {} Pool: Failed to update root on-chain (will retry): {}",
                            pool_name, e
                        );
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
