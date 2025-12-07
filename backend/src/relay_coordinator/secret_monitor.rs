use std::collections::HashSet;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use tokio::time::{interval, Duration};
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

        tokio::try_join!(
            self.monitor_starknet_secrets(),
            self.monitor_zcash_secrets()
        )?;

        Ok(())
    }

    async fn monitor_starknet_secrets(&self) -> Result<()> {
        let mut check_interval = interval(Duration::from_secs(10));

        loop {
            check_interval.tick().await;

            match self.check_starknet_swaps().await {
                Ok(_) => {}
                Err(e) => {
                    error!("❌ Error monitoring Starknet secrets: {}", e);
                }
            }
        }
    }

    async fn check_starknet_swaps(&self) -> Result<()> {
        let pending_swaps = self
            .database
            .get_swaps_awaiting_secret()
            .map_err(|e| anyhow!("Failed to get pending swaps: {}", e))?;

        if pending_swaps.is_empty() {
            debug!("No swaps awaiting secrets on Starknet");
            return Ok(());
        }

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

            match self
                .check_starknet_htlc_for_redemption(nullifier, pool_type)
                .await
            {
                Ok(Some(secret)) => {
                    info!(
                        "🔑 Discovered Starknet secret for swap {}: {}",
                        swap.id, secret
                    );

                    self.database
                        .update_swap_secret(&swap.id, &secret)
                        .map_err(|e| anyhow!("Failed to update secret: {}", e))?;

                    let mut processed = self.processed_htlcs.write().await;
                    processed.insert(nullifier.clone());

                    info!("✅ Secret saved to database for swap {}", swap.id);
                }
                Ok(None) => {
                    debug!("⏳ No secret yet for HTLC nullifier {}", nullifier);
                }
                Err(e) => {
                    warn!("⚠️ Error checking HTLC {} (will retry): {}", nullifier, e);
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
        let (_commitment, _token, _hash_lock, _timelock, state) = self
            .starknet_relayer
            .get_htlc(nullifier, pool_type)
            .await
            .map_err(|e| anyhow!("Failed to get HTLC: {}", e))?;

        if state != 2 {
            return Ok(None);
        }

        self.extract_secret_from_withdrawal_event(nullifier).await
    }

    async fn extract_secret_from_withdrawal_event(
        &self,
        nullifier: &str,
    ) -> Result<Option<String>> {
        let event = match self
            .database
            .get_htlc_event_by_nullifier(nullifier, "htlc_redeemed")
        {
            Ok(Some(evt)) => evt,
            Ok(None) => {
                debug!("No redemption event found yet for nullifier {}", nullifier);
                return Ok(None);
            }
            Err(e) => {
                return Err(anyhow!(
                    "Failed to query indexer events for nullifier {}: {}",
                    nullifier,
                    e
                ));
            }
        };

        if let Some(secret) = event.get("secret").and_then(|s| s.as_str()) {
            info!("🔍 Found secret in withdrawal event: {}", secret);
            return Ok(Some(secret.to_string()));
        }

        debug!("No secret in event data for nullifier {}", nullifier);
        Ok(None)
    }

    async fn monitor_zcash_secrets(&self) -> Result<()> {
        let mut check_interval = interval(Duration::from_secs(10));

        loop {
            check_interval.tick().await;

            match self.check_zcash_swaps().await {
                Ok(_) => {}
                Err(e) => {
                    error!("❌ Error monitoring Zcash secrets: {}", e);
                }
            }
        }
    }

    async fn check_zcash_swaps(&self) -> Result<()> {
        let pending_swaps = self
            .database
            .get_swaps_awaiting_secret()
            .map_err(|e| anyhow!("Failed to get pending swaps: {}", e))?;

        if pending_swaps.is_empty() {
            debug!("No swaps awaiting secrets on Zcash");
            return Ok(());
        }

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
                    info!(
                        "🔑 Discovered Zcash secret for swap {}: {}",
                        swap.id, secret
                    );

                    self.database
                        .update_swap_secret(&swap.id, &secret)
                        .map_err(|e| anyhow!("Failed to update secret: {}", e))?;

                    info!("✅ Secret saved to database for swap {}", swap.id);
                }
                Ok(None) => {
                    debug!("⏳ No secret yet in Zcash tx {}", zcash_txid);
                }
                Err(e) => {
                    warn!(
                        "⚠️ Error checking Zcash tx {} (will retry): {}",
                        zcash_txid, e
                    );
                }
            }
        }

        Ok(())
    }

    async fn check_zcash_transaction_for_secret(&self, txid: &str) -> Result<Option<String>> {
        use serde_json::Value;

        if let Ok(Some(event)) = self
            .database
            .get_htlc_event_by_txid(txid, "htlc_redeemed")
        {
            if let Some(secret) = event.get("secret").and_then(|s| s.as_str()) {
                info!("🔍 Found secret in Zcash indexer event: {}", secret);
                return Ok(Some(secret.to_string()));
            }
        }

        let params = vec![
            serde_json::json!(&self.zcash_relayer.pool_address),
            serde_json::json!(0),
            serde_json::json!(100),
        ];

        let transactions: Vec<Value> = match self
            .zcash_relayer
            .rpc_call("z_listreceivedbyaddress", params)
            .await
        {
            Ok(txs) => txs,
            Err(e) => {
                warn!("Failed to query Zcash transactions: {}", e);
                return Ok(None);
            }
        };

        for tx in transactions {
            let tx_txid = tx["txid"].as_str().unwrap_or("");

            if tx_txid != txid {
                continue;
            }

            if let Some(memo_hex) = tx["memo"].as_str() {
                if let Ok(memo_bytes) = hex::decode(memo_hex) {
                    if let Ok(memo_str) = String::from_utf8(memo_bytes) {
                        if let Some(secret) = self.parse_redeem_memo(&memo_str) {
                            info!("🔍 Found secret in Zcash memo: {}", secret);
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
        let amount_val: f64 = amount
            .parse()
            .map_err(|_| anyhow!("Invalid amount format"))?;

        if amount_val < 10000.0 {
            Ok(PoolType::Fast)
        } else {
            Ok(PoolType::Standard)
        }
    }
}