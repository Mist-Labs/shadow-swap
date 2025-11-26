use std::collections::HashMap;
use std::sync::Arc;

use anyhow::{anyhow, Result};
use tokio::sync::RwLock;
use tokio::time::{interval, sleep, Duration};
use tracing::{debug, error, info, warn};

use crate::crypto::poseidon::PoseidonHasher;
use crate::database::model::SwapPrivacyParams;
use crate::merkle_tree::model::{MerkleTreeManager, PoolType};
use crate::relay_coordinator::model::{
    RelayCoordinator, RelayMetrics, RetryConfig, SwapDirection, SwapOperationState,
};
use crate::{
    database::database::Database,
    models::models::{SwapPair, SwapStatus},
    starknet::relayer::StarknetRelayer,
    zcash::model::ZcashRelayer,
};

impl RelayMetrics {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "total_swaps_processed": self.total_swaps_processed,
            "successful_swaps": self.successful_swaps,
            "failed_swaps": self.failed_swaps,
            "refunded_swaps": self.refunded_swaps,
            "starknet_htlcs_created": self.starknet_htlcs_created,
            "zcash_htlcs_created": self.zcash_htlcs_created,
            "starknet_redemptions": self.starknet_redemptions,
            "zcash_redemptions": self.zcash_redemptions,
            "retry_attempts": self.retry_attempts,
            "last_error": self.last_error,
            "uptime_seconds": self.uptime_seconds,
        })
    }
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            initial_delay_ms: 1000,
            max_delay_ms: 60000,
            backoff_multiplier: 2.0,
        }
    }
}

impl RelayCoordinator {
    pub fn new(
        starknet_relayer: Arc<StarknetRelayer>,
        zcash_relayer: Arc<ZcashRelayer>,
        database: Arc<Database>,
        merkle_tree_manager: Arc<MerkleTreeManager>,
    ) -> Self {
        Self {
            starknet_relayer,
            zcash_relayer,
            database,
            merkle_tree_manager,
            metrics: Arc::new(RwLock::new(RelayMetrics::default())),
            retry_config: RetryConfig::default(),
            operation_states: Arc::new(RwLock::new(HashMap::new())),
            start_time: std::time::Instant::now(),
        }
    }

    pub fn retry_with_config(mut self, config: RetryConfig) -> Self {
        self.retry_config = config;
        self
    }

    pub async fn start(&self) -> Result<()> {
        info!("🎯 Starting relay coordinator");

        let metrics = Arc::clone(&self.metrics);
        let start_time = self.start_time;
        tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(10));
            loop {
                interval.tick().await;
                let mut m = metrics.write().await;
                m.uptime_seconds = start_time.elapsed().as_secs();
            }
        });

        loop {
            if let Err(e) = self.process_pending_swaps().await {
                error!("❌ Error processing pending swaps: {}", e);
                self.record_error(e.to_string()).await;
            }

            sleep(Duration::from_secs(10)).await;
        }
    }

    async fn process_pending_swaps(&self) -> Result<()> {
        let pending_swaps = self
            .database
            .get_pending_swaps()
            .map_err(|e| anyhow!("Failed to get pending swaps: {}", e))?;

        for swap in pending_swaps {
            debug!(
                "🔄 Processing swap: {} (status: {:?})",
                swap.id, swap.status
            );

            {
                let mut metrics = self.metrics.write().await;
                metrics.total_swaps_processed += 1;
            }

            match swap.status {
                SwapStatus::Initiated => {
                    if let Err(e) = self.handle_initiated_swap(&swap).await {
                        error!("Failed to handle initiated swap {}: {}", swap.id, e);
                    }
                }
                SwapStatus::Locked => {
                    if let Err(e) = self.handle_locked_swap(&swap).await {
                        error!("Failed to handle locked swap {}: {}", swap.id, e);
                    }
                }
                _ => {}
            }
        }

        Ok(())
    }

    async fn handle_initiated_swap(&self, swap: &SwapPair) -> Result<()> {
        let direction = self.determine_swap_direction(swap);

        match direction {
            SwapDirection::StarknetToZcash => {
                self.handle_starknet_to_zcash(swap).await?;
            }
            SwapDirection::ZcashToStarknet => {
                self.handle_zcash_to_starknet(swap).await?;
            }
            SwapDirection::Unknown => {
                warn!("Unknown swap direction for swap {}", swap.id);
            }
        }

        Ok(())
    }

    async fn handle_starknet_to_zcash(&self, swap: &SwapPair) -> Result<()> {
        if swap.starknet_htlc_nullifier.is_none() {
            return Err(anyhow!("Starknet HTLC not created yet"));
        }

        if swap.zcash_txid.is_none() {
            info!("🔨 Creating Zcash HTLC for swap {}", swap.id);

            let privacy_params = self
                .database
                .get_swap_privacy_params(&swap.id)
                .map_err(|e| anyhow!("Failed to get privacy params: {}", e))?;

            let zcash_recipient = privacy_params
                .zcash_recipient
                .ok_or_else(|| anyhow!("Missing Zcash recipient"))?;

            let result = self
                .zcash_relayer
                .create_htlc(
                    &zcash_recipient,
                    &swap.zcash_amount,
                    &privacy_params.hash_lock,
                    swap.zcash_timelock,
                )
                .await
                .map_err(|e| e.to_string());

            match result {
                Ok(txid) => {
                    self.database
                        .update_zcash_txid(&swap.id, &txid)
                        .map_err(|e| anyhow!("Failed to update Zcash txid: {}", e))?;
                    let mut metrics = self.metrics.write().await;
                    metrics.zcash_htlcs_created += 1;
                }
                Err(e) => {
                    error!("❌ Failed to create Zcash HTLC: {}", e);
                    self.mark_swap_failed(&swap.id, &format!("Zcash HTLC creation failed: {}", e))
                        .await?;
                    return Err(anyhow!("Zcash HTLC creation failed: {}", e));
                }
            }
        }

        let updated_swap = self
            .database
            .get_swap_by_id(&swap.id)
            .map_err(|e| anyhow!("Failed to get swap: {}", e))?;
        if let Some(s) = updated_swap {
            if s.starknet_htlc_nullifier.is_some() && s.zcash_txid.is_some() {
                self.database
                    .update_swap_status(&swap.id, SwapStatus::Locked)
                    .map_err(|e| anyhow!("Failed to update swap status: {}", e))?;
                info!("✅ Swap {} locked on both chains", swap.id);
            }
        }

        Ok(())
    }

    async fn handle_zcash_to_starknet(&self, swap: &SwapPair) -> Result<()> {
        if swap.zcash_txid.is_none() {
            return Err(anyhow!("Zcash HTLC not created yet"));
        }

        if swap.starknet_htlc_nullifier.is_none() {
            info!("🔨 Creating Starknet HTLC for swap {}", swap.id);

            let privacy_params = self
                .database
                .get_swap_privacy_params(&swap.id)
                .map_err(|e| anyhow!("Failed to get privacy params: {}", e))?;

            let token_address = privacy_params
                .token_address
                .ok_or_else(|| anyhow!("Missing token address"))?;
            let amount_commitment = privacy_params
                .amount_commitment
                .ok_or_else(|| anyhow!("Missing amount commitment"))?;

            let nullifier =
                PoseidonHasher::generate_nullifier(&amount_commitment, &swap.hash_lock)?;

            let pool_type = self.determine_pool_type(&swap.starknet_amount)?;

            let amount: u128 = swap
                .starknet_amount
                .parse()
                .map_err(|_| anyhow!("Invalid amount format"))?;

            let root = self
                .starknet_relayer
                .get_current_root(pool_type)
                .await
                .map_err(|e| anyhow!("Failed to get current root: {}", e))?;

            let membership_proof = self
                .merkle_tree_manager
                .generate_proof(&token_address, &amount_commitment, pool_type)
                .await
                .map_err(|e| anyhow!("Failed to generate merkle proof: {}", e))?;

            if membership_proof.root != root {
                return Err(anyhow!(
                    "Merkle proof root mismatch - local: {}, on-chain: {}",
                    membership_proof.root,
                    root
                ));
            }

            let result = self
                .starknet_relayer
                .create_htlc(
                    &token_address,
                    &nullifier,
                    &root,
                    &amount_commitment,
                    amount,
                    membership_proof.path,
                    membership_proof.indices.iter().map(|&i| i as u8).collect(),
                    &swap.hash_lock,
                    swap.starknet_timelock,
                    pool_type,
                )
                .await
                .map_err(|e| e.to_string());

            match result {
                Ok(tx_hash) => {
                    self.database
                        .update_starknet_htlc_address(&swap.id, &nullifier)
                        .map_err(|e| anyhow!("Failed to update Starknet HTLC nullifier: {}", e))?;

                    self.database
                        .add_note_to_swap(&swap.id, &format!("Starknet HTLC tx: {}", tx_hash))
                        .ok();

                    let mut metrics = self.metrics.write().await;
                    metrics.starknet_htlcs_created += 1;
                    info!("✅ Starknet HTLC created: {}", tx_hash);
                }
                Err(e) => {
                    error!("❌ Failed to create Starknet HTLC: {}", e);
                    self.mark_swap_failed(
                        &swap.id,
                        &format!("Starknet HTLC creation failed: {}", e),
                    )
                    .await?;
                    return Err(anyhow!("Starknet HTLC creation failed: {}", e));
                }
            }
        }

        Ok(())
    }

    async fn handle_locked_swap(&self, swap: &SwapPair) -> Result<()> {
        let direction = self.determine_swap_direction(swap);
        let privacy_params = self
            .database
            .get_swap_privacy_params(&swap.id)
            .map_err(|e| anyhow!("Failed to get privacy params: {}", e))?;

        let now = chrono::Utc::now().timestamp() as u64;
        if now > swap.starknet_timelock || now > swap.zcash_timelock {
            info!(
                "⏰ Timelock expired for swap {}, initiating refund",
                swap.id
            );
            return self.handle_refund(swap, direction, &privacy_params).await;
        }

        match direction {
            SwapDirection::StarknetToZcash => {
                self.redeem_zcash_for_user(swap, &privacy_params).await?;
                self.redeem_starknet_to_pool(swap, &privacy_params).await?;
            }
            SwapDirection::ZcashToStarknet => {
                self.redeem_starknet_for_user(swap, &privacy_params).await?;
                self.redeem_zcash_to_pool(swap, &privacy_params).await?;
            }
            SwapDirection::Unknown => {
                return Err(anyhow!("Cannot redeem swap with unknown direction"));
            }
        }

        Ok(())
    }

    async fn redeem_zcash_for_user(
        &self,
        swap: &SwapPair,
        privacy_params: &SwapPrivacyParams,
    ) -> Result<()> {
        if let Some(zcash_recipient) = &privacy_params.zcash_recipient {
            let secret = swap
                .secret
                .as_ref()
                .ok_or_else(|| anyhow!("Secret not available yet"))?;

            let result = self
                .zcash_relayer
                .redeem_htlc(zcash_recipient, &swap.zcash_amount, secret)
                .await
                .map_err(|e| e.to_string());

            match result {
                Ok(txid) => {
                    info!("✅ Zcash redeemed for user: {}", txid);
                    let mut metrics = self.metrics.write().await;
                    metrics.zcash_redemptions += 1;
                }
                Err(e) => {
                    warn!("⚠️ Zcash redemption failed: {}", e);
                }
            }
        }
        Ok(())
    }

    async fn redeem_starknet_to_pool(
        &self,
        swap: &SwapPair,
        privacy_params: &SwapPrivacyParams,
    ) -> Result<()> {
        if let Some(nullifier) = &swap.starknet_htlc_nullifier {
            let secret = swap
                .secret
                .as_ref()
                .ok_or_else(|| anyhow!("Secret not available yet"))?;

            let token_address = privacy_params
                .token_address
                .as_ref()
                .ok_or_else(|| anyhow!("Missing token address"))?;

            let pool_type = self.determine_pool_type(&swap.starknet_amount)?;
            let pool_address = match pool_type {
                PoolType::Fast => self.starknet_relayer.fast_pool_address,
                PoolType::Standard => self.starknet_relayer.standard_pool_address,
            };
            let pool_recipient_hex = format!("0x{:x}", pool_address);

            let result = self
                .starknet_relayer
                .redeem_htlc(
                    token_address,
                    nullifier,
                    &pool_recipient_hex,
                    secret,
                    pool_type,
                )
                .await
                .map_err(|e| e.to_string());

            match result {
                Ok(txid) => {
                    info!("✅ Starknet redeemed to pool: {}", txid);
                    let mut metrics = self.metrics.write().await;
                    metrics.starknet_redemptions += 1;

                    self.database
                        .update_swap_status(&swap.id, SwapStatus::Redeemed)
                        .map_err(|e| anyhow!("Failed to update swap status: {}", e))?;
                    metrics.successful_swaps += 1;
                }
                Err(e) => {
                    error!("❌ Starknet redemption failed: {}", e);
                    self.database
                        .add_note_to_swap(&swap.id, "CRITICAL: Zcash redeemed but Starknet failed")
                        .map_err(|e| anyhow!("Failed to add note: {}", e))?;
                    return Err(anyhow!("Starknet redemption failed: {}", e));
                }
            }
        }
        Ok(())
    }

    async fn redeem_starknet_for_user(
        &self,
        swap: &SwapPair,
        privacy_params: &SwapPrivacyParams,
    ) -> Result<()> {
        if let Some(nullifier) = &swap.starknet_htlc_nullifier {
            let secret = swap
                .secret
                .as_ref()
                .ok_or_else(|| anyhow!("Secret not available yet"))?;

            let token_address = privacy_params
                .token_address
                .as_ref()
                .ok_or_else(|| anyhow!("Missing token address"))?;

            let stealth_participant = privacy_params
                .stealth_participant
                .as_ref()
                .ok_or_else(|| anyhow!("Missing stealth participant"))?;

            let pool_type = self.determine_pool_type(&swap.starknet_amount)?;

            let result = self
                .starknet_relayer
                .redeem_htlc(
                    token_address,
                    nullifier,
                    stealth_participant,
                    secret,
                    pool_type,
                )
                .await
                .map_err(|e| e.to_string());

            match result {
                Ok(txid) => {
                    info!("✅ Starknet redeemed for user: {}", txid);
                    let mut metrics = self.metrics.write().await;
                    metrics.starknet_redemptions += 1;
                }
                Err(e) => {
                    warn!("⚠️ Starknet redemption failed: {}", e);
                }
            }
        }
        Ok(())
    }

    async fn redeem_zcash_to_pool(
        &self,
        swap: &SwapPair,
        privacy_params: &SwapPrivacyParams,
    ) -> Result<()> {
        if let Some(zcash_recipient) = &privacy_params.zcash_recipient {
            let secret = swap
                .secret
                .as_ref()
                .ok_or_else(|| anyhow!("Secret not available yet"))?;

            let result = self
                .zcash_relayer
                .redeem_htlc(zcash_recipient, &swap.zcash_amount, secret)
                .await
                .map_err(|e| e.to_string());

            match result {
                Ok(txid) => {
                    info!("✅ Zcash redeemed to pool: {}", txid);
                    let mut metrics = self.metrics.write().await;
                    metrics.zcash_redemptions += 1;

                    self.database
                        .update_swap_status(&swap.id, SwapStatus::Redeemed)
                        .map_err(|e| anyhow!("Failed to update swap status: {}", e))?;
                    metrics.successful_swaps += 1;
                }
                Err(e) => {
                    error!("❌ Zcash redemption failed: {}", e);
                    self.database
                        .add_note_to_swap(&swap.id, "CRITICAL: Starknet redeemed but Zcash failed")
                        .map_err(|e| anyhow!("Failed to add note: {}", e))?;
                    return Err(anyhow!("Zcash redemption failed: {}", e));
                }
            }
        }
        Ok(())
    }

    async fn handle_refund(
        &self,
        swap: &SwapPair,
        direction: SwapDirection,
        privacy_params: &SwapPrivacyParams,
    ) -> Result<()> {
        match direction {
            SwapDirection::StarknetToZcash => {
                if let Some(nullifier) = &swap.starknet_htlc_nullifier {
                    let token_address = privacy_params
                        .token_address
                        .as_ref()
                        .ok_or_else(|| anyhow!("Missing token address"))?;

                    let stealth_initiator = privacy_params
                        .stealth_initiator
                        .as_ref()
                        .ok_or_else(|| anyhow!("Missing stealth initiator"))?;

                    let pool_type = self.determine_pool_type(&swap.starknet_amount)?;

                    self.starknet_relayer
                        .refund_htlc(token_address, nullifier, stealth_initiator, pool_type)
                        .await
                        .map_err(|e| anyhow!("Starknet refund failed: {}", e))?;
                }
            }
            SwapDirection::ZcashToStarknet => {
                if let Some(zcash_recipient) = &privacy_params.zcash_recipient {
                    self.zcash_relayer
                        .refund_htlc(zcash_recipient, &swap.zcash_amount, "timelock_expired")
                        .await
                        .map_err(|e| anyhow!("Zcash refund failed: {}", e))?;
                }
            }
            SwapDirection::Unknown => {}
        }

        self.database
            .update_swap_status(&swap.id, SwapStatus::Refunded)
            .map_err(|e| anyhow!("Failed to update swap status: {}", e))?;
        let mut metrics = self.metrics.write().await;
        metrics.refunded_swaps += 1;

        info!("♻️ Swap {} refunded", swap.id);
        Ok(())
    }

    fn determine_swap_direction(&self, swap: &SwapPair) -> SwapDirection {
        match (
            swap.starknet_htlc_nullifier.is_some(),
            swap.zcash_txid.is_some(),
        ) {
            (true, false) => SwapDirection::StarknetToZcash,
            (false, true) => SwapDirection::ZcashToStarknet,
            _ => SwapDirection::Unknown,
        }
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

    async fn mark_swap_failed(&self, swap_id: &str, reason: &str) -> Result<()> {
        error!("❌ Marking swap {} as failed: {}", swap_id, reason);

        self.database
            .update_swap_status(swap_id, SwapStatus::Failed)
            .map_err(|e| anyhow!("Failed to update swap status: {}", e))?;
        self.database
            .add_note_to_swap(swap_id, reason)
            .map_err(|e| anyhow!("Failed to add note: {}", e))?;

        let mut metrics = self.metrics.write().await;
        metrics.failed_swaps += 1;

        Ok(())
    }

    async fn record_error(&self, error: String) {
        let mut metrics = self.metrics.write().await;
        metrics.last_error = Some(error);
    }

    pub async fn get_metrics(&self) -> RelayMetrics {
        self.metrics.read().await.clone()
    }

    pub async fn get_operation_states(&self) -> Vec<SwapOperationState> {
        self.operation_states
            .read()
            .await
            .values()
            .cloned()
            .collect()
    }
}
