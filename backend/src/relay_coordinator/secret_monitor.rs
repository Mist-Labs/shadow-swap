// src/relay_coordinator/secret_monitor.rs
use std::collections::HashSet;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info, warn};

use crate::database::database::Database;
use crate::merkle_tree::model::PoolType;
use crate::starknet::relayer::StarknetRelayer;
use crate::zcash::model::ZcashRelayer;

pub struct SecretMonitor {
    starknet_relayer: Arc<StarknetRelayer>,
    zcash_relayer: Arc<ZcashRelayer>,
    database: Arc<Database>,
    processed_htlcs: Arc<tokio::sync::RwLock<HashSet<String>>>,
}

impl SecretMonitor {
    pub fn new(
        starknet_relayer: Arc<StarknetRelayer>,
        zcash_relayer: Arc<ZcashRelayer>,
        database: Arc<Database>,
    ) -> Self {
        Self {
            starknet_relayer,
            zcash_relayer,
            database,
            processed_htlcs: Arc::new(tokio::sync::RwLock::new(HashSet::new())),
        }
    }

    pub async fn start(&self) -> Result<()> {
        info!("🔍 Starting secret monitor");

        let starknet_monitor = self.clone_for_starknet();
        let zcash_monitor = self.clone_for_zcash();

        tokio::spawn(async move {
            loop {
                if let Err(e) = starknet_monitor.monitor_starknet_secrets().await {
                    error!("❌ Starknet monitor error: {}", e);
                }
                sleep(Duration::from_secs(12)).await;
            }
        });

        tokio::spawn(async move {
            loop {
                if let Err(e) = zcash_monitor.monitor_zcash_secrets().await {
                    error!("❌ Zcash monitor error: {}", e);
                }
                sleep(Duration::from_secs(75)).await;
            }
        });

        Ok(())
    }

    async fn monitor_starknet_secrets(&self) -> Result<()> {
        let pending_swaps = self.database.get_swaps_awaiting_secret()
            .map_err(|e| anyhow!("Failed to get pending swaps: {}", e))?;

        for swap in pending_swaps {
            if swap.secret.is_some() {
                continue;
            }

            let nullifier = match &swap.starknet_htlc_nullifier {
                Some(addr) => addr,
                None => continue,
            };

            {
                let processed = self.processed_htlcs.read().await;
                if processed.contains(nullifier) {
                    continue;
                }
            }

            let pool_type = self.determine_pool_type(&swap.starknet_amount)?;

            match self.check_starknet_htlc_for_redemption(nullifier, pool_type).await {
                Ok(Some(secret)) => {
                    info!("🔑 Discovered Starknet secret for swap {}: {}", swap.id, secret);
                    
                    self.database.update_swap_secret(&swap.id, &secret)
                        .map_err(|e| anyhow!("Failed to update secret: {}", e))?;
                    
                    let mut processed = self.processed_htlcs.write().await;
                    processed.insert(nullifier.clone());
                    
                    info!("✅ Secret saved to database for swap {}", swap.id);
                }
                Ok(None) => {
                    debug!("⏳ No secret yet for HTLC nullifier {}", nullifier);
                }
                Err(e) => {
                    warn!("⚠️ Error checking HTLC {}: {}", nullifier, e);
                }
            }
        }

        Ok(())
    }

    async fn check_starknet_htlc_for_redemption(
        &self,
        nullifier: &str,
        pool_type: PoolType,
    ) -> Result<Option<String>> {
        let (commitment, token, hash_lock, timelock, state) = self.starknet_relayer
            .get_htlc(nullifier, pool_type)
            .await
            .map_err(|e| anyhow!("Failed to get HTLC: {}", e))?;

        if state != 1 {
            return Ok(None);
        }

        self.extract_secret_from_withdrawal_event(nullifier).await
    }

    // TODO: IMPLEMENT WHEN INDEXER IS COMPLETED
    async fn extract_secret_from_withdrawal_event(&self, nullifier: &str) -> Result<Option<String>> {
        Ok(None)
    }

    async fn monitor_zcash_secrets(&self) -> Result<()> {
        let pending_swaps = self.database.get_swaps_awaiting_secret()
            .map_err(|e| anyhow!("Failed to get pending swaps: {}", e))?;

        for swap in pending_swaps {
            if swap.secret.is_some() {
                continue;
            }

            let zcash_txid = match &swap.zcash_txid {
                Some(txid) => txid,
                None => continue,
            };

            match self.check_zcash_transaction_for_secret(zcash_txid).await {
                Ok(Some(secret)) => {
                    info!("🔑 Discovered Zcash secret for swap {}: {}", swap.id, secret);
                    
                    self.database.update_swap_secret(&swap.id, &secret)
                        .map_err(|e| anyhow!("Failed to update secret: {}", e))?;
                    
                    info!("✅ Secret saved to database for swap {}", swap.id);
                }
                Ok(None) => {
                    debug!("⏳ No secret yet in Zcash tx {}", zcash_txid);
                }
                Err(e) => {
                    warn!("⚠️ Error checking Zcash tx {}: {}", zcash_txid, e);
                }
            }
        }

        Ok(())
    }

    async fn check_zcash_transaction_for_secret(&self, txid: &str) -> Result<Option<String>> {
        use serde_json::Value;

        let params = vec![
            serde_json::json!(100),
            serde_json::json!(0),
        ];

        let transactions: Vec<Value> = self.zcash_relayer.rpc_call("z_listreceivedbyaddress", params).await
            .map_err(|e| anyhow!("Failed to list received transactions: {}", e))?;

        for tx in transactions {
            let tx_txid = tx["txid"].as_str().unwrap_or("");
            
            if tx_txid != txid {
                continue;
            }

            if let Some(memo_hex) = tx["memo"].as_str() {
                if let Ok(memo_bytes) = hex::decode(memo_hex) {
                    if let Ok(memo_str) = String::from_utf8(memo_bytes) {
                        if let Some(secret) = self.parse_redeem_memo(&memo_str) {
                            return Ok(Some(secret));
                        }
                    }
                }
            }
        }

        Ok(None)
    }

    fn parse_redeem_memo(&self, memo: &str) -> Option<String> {
        let parts: Vec<&str> = memo.split('|').collect();
        
        if parts.len() != 2 {
            return None;
        }

        if parts[0] != "REDEEM" {
            return None;
        }

        let secret = parts[1].trim();
        
        if secret.is_empty() {
            return None;
        }

        Some(secret.to_string())
    }

    fn determine_pool_type(&self, amount: &str) -> Result<PoolType> {
        let amount_val: f64 = amount.parse()
            .map_err(|_| anyhow!("Invalid amount format"))?;

        if amount_val < 10000.0 {
            Ok(PoolType::Fast)
        } else {
            Ok(PoolType::Standard)
        }
    }

    fn clone_for_starknet(&self) -> Self {
        Self {
            starknet_relayer: Arc::clone(&self.starknet_relayer),
            zcash_relayer: Arc::clone(&self.zcash_relayer),
            database: Arc::clone(&self.database),
            processed_htlcs: Arc::clone(&self.processed_htlcs),
        }
    }

    fn clone_for_zcash(&self) -> Self {
        Self {
            starknet_relayer: Arc::clone(&self.starknet_relayer),
            zcash_relayer: Arc::clone(&self.zcash_relayer),
            database: Arc::clone(&self.database),
            processed_htlcs: Arc::clone(&self.processed_htlcs),
        }
    }
}