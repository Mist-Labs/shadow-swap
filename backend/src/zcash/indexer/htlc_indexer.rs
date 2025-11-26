use std::{sync::Arc, time::Duration};

use anyhow::{anyhow, Context, Result};
use hmac::{Hmac, Mac};
use reqwest::Client;
use sha2::Sha256;
use tokio::time::interval;
use tracing::{debug, error, info, warn};

use crate::{
    database::database::Database,
    zcash::{
        indexer::model::{
            BlockInfo, HTLCState, IndexerEventPayload, ShieldedOutput, ShieldedSpend, ZcashHTLC,
            ZcashIndexer, ZcashTransaction,
        },
        model::ZcashRelayer,
    },
};

type HmacSha256 = Hmac<Sha256>;

impl ZcashIndexer {
    pub fn new(
        relayer: Arc<ZcashRelayer>,
        database: Arc<Database>,
        relayer_api_url: String,
        hmac_secret: String,
        monitored_addresses: Vec<String>,
        start_block: u32,
    ) -> Self {
        Self {
            relayer,
            database,
            http_client: Client::new(),
            relayer_api_url,
            hmac_secret,
            monitored_addresses: monitored_addresses.into_iter().collect(),
            last_processed_block: start_block,
            min_confirmations: 3,
        }
    }

    pub async fn start(&mut self) -> Result<()> {
        info!("🔍 Starting Zcash HTLC Indexer");
        info!("📍 Starting from block: {}", self.last_processed_block);
        info!("🎯 Monitoring {} addresses", self.monitored_addresses.len());

        let mut tick = interval(Duration::from_secs(30));
        loop {
            tick.tick().await;

            if let Err(e) = self.process_new_blocks().await {
                error!("❌ Error processing blocks: {}", e);
            }
        }
    }

    async fn process_new_blocks(&mut self) -> Result<()> {
        let current_height = self.get_block_height().await?;

        if current_height <= self.last_processed_block {
            debug!("No new blocks to process");
            return Ok(());
        }

        let start_block = self.last_processed_block + 1;
        let end_block = (current_height - self.min_confirmations).min(start_block + 100);

        info!(
            "📦 Processing blocks {} to {} (current: {})",
            start_block, end_block, current_height
        );

        for height in start_block..=end_block {
            if let Err(e) = self.process_block(height).await {
                error!("❌ Error processing block {}: {}", height, e);
                continue;
            }

            self.last_processed_block = height;

            if height % 10 == 0 {
                self.save_checkpoint(height)?;
            }
        }

        Ok(())
    }

    async fn process_block(&self, height: u32) -> Result<()> {
        let block = self.get_block_by_height(height).await?;

        debug!(
            "Processing block {} with {} transactions",
            height,
            block.tx.len()
        );

        for txid in &block.tx {
            if let Err(e) = self.process_transaction(txid, block.time).await {
                warn!("⚠️ Error processing tx {}: {}", txid, e);
            }
        }

        Ok(())
    }

    async fn process_transaction(&self, txid: &str, block_time: u64) -> Result<()> {
        let tx = self.get_transaction(txid).await?;

        if tx.confirmations < self.min_confirmations {
            return Ok(());
        }

        if let Some(outputs) = &tx.vShieldedOutput {
            self.process_shielded_outputs(txid, outputs, block_time)
                .await?;
        }

        if let Some(spends) = &tx.vShieldedSpend {
            self.process_shielded_spends(txid, spends, block_time)
                .await?;
        }

        Ok(())
    }

    async fn process_shielded_outputs(
        &self,
        txid: &str,
        outputs: &[ShieldedOutput],
        block_time: u64,
    ) -> Result<()> {
        for output in outputs {
            if let Ok(memo) = self.try_decrypt_memo(&output.encCiphertext).await {
                if memo.starts_with("HTLC:") {
                    info!("🔨 Detected HTLC creation in tx: {}", txid);

                    if let Ok(htlc) = ZcashHTLC::decode_memo(&hex::encode(&memo), "") {
                        self.handle_htlc_created(txid, &htlc, block_time).await?;
                    }
                }
            }
        }

        Ok(())
    }

    async fn process_shielded_spends(
        &self,
        txid: &str,
        spends: &[ShieldedSpend],
        block_time: u64,
    ) -> Result<()> {
        // Check if this spend is related to any active HTLCs
        for spend in spends {
            if let Some(htlc_tx) = self.find_htlc_by_nullifier(&spend.nullifier)? {
                info!("🔓 Detected HTLC spend in tx: {}", txid);

                // Try to extract secret or determine if refund
                if let Ok(secret) = self.extract_secret_from_spend(txid).await {
                    self.handle_htlc_redeemed(txid, &htlc_tx, &secret, block_time)
                        .await?;
                } else {
                    self.handle_htlc_refunded(txid, &htlc_tx, block_time)
                        .await?;
                }
            }
        }

        Ok(())
    }

    async fn handle_htlc_created(
        &self,
        txid: &str,
        htlc: &ZcashHTLC,
        timestamp: u64,
    ) -> Result<()> {
        info!("📝 Recording HTLC creation: {}", txid);

        // Store in database
        self.database
            .record_zcash_htlc(txid, htlc)
            .map_err(|e| anyhow!("Failed to record Zcash HTLC {}: {}", txid, e))?; // <-- Fix Applied Here

        let payload = IndexerEventPayload {
            event_type: "htlc_created".to_string(),
            chain: "zcash".to_string(),
            transaction_hash: txid.to_string(),
            commitment: None,
            hash_lock: Some(htlc.hash_lock.clone()),
            nullifier: None,
            secret: None,
            amount: Some(htlc.amount.to_string()),
            timestamp,
        };

        self.send_event_to_relayer(payload).await?;
        Ok(())
    }

    async fn handle_htlc_redeemed(
        &self,
        txid: &str,
        htlc_txid: &str,
        secret: &str,
        timestamp: u64,
    ) -> Result<()> {
        info!(
            "✅ Recording HTLC redemption: {} for HTLC {}",
            txid, htlc_txid
        );

        self.database
            .update_zcash_htlc_state(htlc_txid, HTLCState::Redeemed)
            .map_err(|e| {
                anyhow!(
                    "Failed to update Zcash HTLC state to Redeemed for {}: {}",
                    htlc_txid,
                    e
                )
            })?;

        let payload = IndexerEventPayload {
            event_type: "htlc_redeemed".to_string(),
            chain: "zcash".to_string(),
            transaction_hash: txid.to_string(),
            commitment: None,
            hash_lock: None,
            nullifier: None,
            secret: Some(secret.to_string()),
            amount: None,
            timestamp,
        };

        self.send_event_to_relayer(payload).await?;
        Ok(())
    }

    async fn handle_htlc_refunded(
        &self,
        txid: &str,
        htlc_txid: &str,
        timestamp: u64,
    ) -> Result<()> {
        info!("♻️ Recording HTLC refund: {} for HTLC {}", txid, htlc_txid);

        self.database
            .update_zcash_htlc_state(htlc_txid, HTLCState::Refunded)
            .map_err(|e| {
                anyhow!(
                    "Failed to update Zcash HTLC state to Refunded for {}: {}",
                    htlc_txid,
                    e
                )
            })?;

        let payload = IndexerEventPayload {
            event_type: "htlc_refunded".to_string(),
            chain: "zcash".to_string(),
            transaction_hash: txid.to_string(),
            commitment: None,
            hash_lock: None,
            nullifier: None,
            secret: None,
            amount: None,
            timestamp,
        };

        self.send_event_to_relayer(payload).await?;
        Ok(())
    }

    /// Send event to relayer API with HMAC authentication
    async fn send_event_to_relayer(&self, payload: IndexerEventPayload) -> Result<()> {
        let timestamp = chrono::Utc::now().timestamp().to_string();
        let body = serde_json::to_string(&payload)?;

        // Generate HMAC signature
        let message = format!("{}{}", timestamp, body);
        let mut mac = HmacSha256::new_from_slice(self.hmac_secret.as_bytes())
            .map_err(|e| anyhow!("HMAC error: {}", e))?;
        mac.update(message.as_bytes());
        let signature = hex::encode(mac.finalize().into_bytes());

        let response = self
            .http_client
            .post(format!("{}/indexer/event", self.relayer_api_url))
            .header("x-timestamp", timestamp)
            .header("x-signature", signature)
            .header("content-type", "application/json")
            .body(body)
            .send()
            .await?;

        if !response.status().is_success() {
            let status = response.status();
            let error_text = response.text().await.unwrap_or_default();
            return Err(anyhow!("Relayer API error {}: {}", status, error_text));
        }

        debug!("✅ Event sent to relayer successfully");
        Ok(())
    }

    async fn get_block_height(&self) -> Result<u32> {
        self.relayer
            .rpc_call("getblockcount", vec![])
            .await
            .map_err(|e| anyhow!("Failed to get block height: {}", e))
    }

    async fn get_block_by_height(&self, height: u32) -> Result<BlockInfo> {
        let hash: String = self
            .relayer
            .rpc_call("getblockhash", vec![serde_json::json!(height)])
            .await
            .map_err(|e| anyhow!("Failed to get block hash: {}", e))?;

        self.relayer
            .rpc_call("getblock", vec![serde_json::json!(hash)])
            .await
            .map_err(|e| anyhow!("Failed to get block info: {}", e))
    }

    async fn get_transaction(&self, txid: &str) -> Result<ZcashTransaction> {
        self.relayer
            .rpc_call(
                "getrawtransaction",
                vec![serde_json::json!(txid), serde_json::json!(1)],
            )
            .await
            .map_err(|e| anyhow!("Failed to get transaction: {}", e))
    }

    async fn try_decrypt_memo(&self, encrypted: &str) -> Result<String> {
        self.relayer
            .rpc_call("z_viewtransaction", vec![serde_json::json!(encrypted)])
            .await
            .map(|v: serde_json::Value| v.to_string())
            .map_err(|e| anyhow!("Failed to decrypt memo: {}", e))
    }

    async fn extract_secret_from_spend(&self, txid: &str) -> Result<String> {
        let tx = self.get_transaction(txid).await?;

        if let Some(outputs) = &tx.vShieldedOutput {
            for output in outputs {
                if let Ok(memo) = self.try_decrypt_memo(&output.encCiphertext).await {
                    if memo.starts_with("REDEEM:") {
                        let secret = memo.strip_prefix("REDEEM:").unwrap_or("");
                        if !secret.is_empty() {
                            return Ok(secret.to_string());
                        }
                    }
                }
            }
        }

        Err(anyhow!("No secret found in transaction"))
    }

    fn find_htlc_by_nullifier(&self, nullifier: &str) -> Result<Option<String>> {
        self.database
            .get_zcash_htlc_by_nullifier(nullifier)
            .map_err(|e| anyhow!("Database error fetching HTLC by nullifier: {}", e))
    }

    fn save_checkpoint(&self, height: u32) -> Result<()> {
        self.database
            .save_indexer_checkpoint("zcash", height)
            .map_err(|e| anyhow!("Failed to save Zcash indexer checkpoint: {}", e))
    }
}
