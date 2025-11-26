use std::{sync::Arc, time::Duration};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use tokio::time::sleep;
use tracing::info;

use crate::{
    config::model::ZcashConfig,
    database::database::Database,
    zcash::model::{ZcashPrivacyParams, ZcashRelayer, ZcashRpcRequest, ZcashRpcResponse},
};

impl ZcashRelayer {
    pub fn new(config: ZcashConfig, database: Arc<Database>) -> Self {
        info!("🔒 Initializing Zcash relayer");

        Self {
            rpc_url: config.rpc_url,
            rpc_user: config.rpc_user,
            rpc_password: config.rpc_password,
            wallet_name: config.wallet_name,
            client: reqwest::Client::new(),
            database,
        }
    }

    pub fn generate_privacy_params(
        &self,
        zcash_address: &str,
        amount: &str,
        timestamp: i64,
    ) -> Result<ZcashPrivacyParams, Box<dyn std::error::Error>> {
        let seed = format!("{}:{}:{}", zcash_address, amount, timestamp);

        // Generate secret
        let mut hasher = Sha256::new();
        hasher.update(seed.as_bytes());
        hasher.update(b":secret");
        let secret = hex::encode(hasher.finalize());

        // Generate hash_lock
        let mut hasher = Sha256::new();
        hasher.update(secret.as_bytes());
        let hash_lock = hex::encode(hasher.finalize());

        Ok(ZcashPrivacyParams { secret, hash_lock })
    }

    // ==================== HTLC Operations ====================

    pub async fn create_htlc(
        &self,
        recipient: &str,
        amount: &str,
        hash_lock: &str,
        timelock: u64,
    ) -> Result<String, Box<dyn std::error::Error>> {
        info!("🔨 Creating Zcash shielded HTLC");

        let amount_f64: f64 = amount.parse()?;

        // Encode HTLC params in memo
        let memo = format!("HTLC|{}|{}", hash_lock, timelock);
        let memo_hex = hex::encode(memo.as_bytes());

        let from_address = "";
        let amounts = serde_json::json!([{
            "address": recipient,
            "amount": amount_f64,
            "memo": memo_hex
        }]);

        let params = vec![
            serde_json::json!(from_address),
            amounts,
            serde_json::json!(1),
            serde_json::json!(0.0001),
        ];

        let opid: String = self.rpc_call("z_sendmany", params).await?;
        info!("📤 Zcash operation ID: {}", opid);

        let txid = self.wait_for_operation(&opid).await?;
        info!("✅ Zcash HTLC created: {}", txid);
        Ok(txid)
    }

    pub async fn redeem_htlc(
        &self,
        recipient: &str,
        amount: &str,
        secret: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        info!("🔓 Redeeming Zcash HTLC");

        let amount_f64: f64 = amount.parse()?;
        let memo = format!("REDEEM|{}", secret);
        let memo_hex = hex::encode(memo.as_bytes());

        let from_address = "";
        let amounts = serde_json::json!([{
            "address": recipient,
            "amount": amount_f64,
            "memo": memo_hex
        }]);

        let params = vec![
            serde_json::json!(from_address),
            amounts,
            serde_json::json!(1),
            serde_json::json!(0.0001),
        ];

        let opid: String = self.rpc_call("z_sendmany", params).await?;
        let txid = self.wait_for_operation(&opid).await?;

        info!("✅ Zcash redeemed: {}", txid);
        Ok(txid)
    }

    pub async fn refund_htlc(
        &self,
        recipient: &str,
        amount: &str,
        reason: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        info!("♻️ Refunding Zcash HTLC");

        let amount_f64: f64 = amount.parse()?;
        let memo = format!("REFUND|{}", reason);
        let memo_hex = hex::encode(memo.as_bytes());

        let from_address = "";
        let amounts = serde_json::json!([{
            "address": recipient,
            "amount": amount_f64,
            "memo": memo_hex
        }]);

        let params = vec![
            serde_json::json!(from_address),
            amounts,
            serde_json::json!(1),
            serde_json::json!(0.0001),
        ];

        let opid: String = self.rpc_call("z_sendmany", params).await?;
        let txid = self.wait_for_operation(&opid).await?;

        info!("✅ Zcash refunded: {}", txid);
        Ok(txid)
    }

    // ==================== Helper Methods ====================

    pub async fn rpc_call<T: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: Vec<serde_json::Value>,
    ) -> Result<T, Box<dyn std::error::Error>> {
        let request = ZcashRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: "1".to_string(),
            method: method.to_string(),
            params,
        };

        let response = self
            .client
            .post(&self.rpc_url)
            .basic_auth(&self.rpc_user, Some(&self.rpc_password))
            .json(&request)
            .send()
            .await?;

        let rpc_response: ZcashRpcResponse<T> = response.json().await?;

        if let Some(error) = rpc_response.error {
            return Err(format!("RPC error {}: {}", error.code, error.message).into());
        }

        rpc_response
            .result
            .ok_or_else(|| "No result in RPC response".into())
    }

    async fn wait_for_operation(&self, opid: &str) -> Result<String, Box<dyn std::error::Error>> {
        info!("⏳ Waiting for Zcash operation to complete...");

        let mut attempts = 0;
        let max_attempts = 60;

        loop {
            attempts += 1;

            #[derive(Deserialize)]
            struct OperationStatus {
                status: String,
                result: Option<serde_json::Value>,
                error: Option<serde_json::Value>,
            }

            let statuses: Vec<OperationStatus> = self
                .rpc_call("z_getoperationstatus", vec![serde_json::json!([opid])])
                .await?;

            if let Some(status) = statuses.first() {
                match status.status.as_str() {
                    "success" => {
                        if let Some(result) = &status.result {
                            if let Some(txid) = result.get("txid") {
                                if let Some(txid_str) = txid.as_str() {
                                    info!("✅ Operation completed");
                                    return Ok(txid_str.to_string());
                                }
                            }
                        }
                        return Err("Operation succeeded but no txid found".into());
                    }
                    "failed" => {
                        let error_msg = status
                            .error
                            .as_ref()
                            .and_then(|e| e.get("message"))
                            .and_then(|m| m.as_str())
                            .unwrap_or("Unknown error");
                        return Err(format!("Operation failed: {}", error_msg).into());
                    }
                    "executing" | "queued" => {
                        if attempts >= max_attempts {
                            return Err(
                                format!("Operation timeout after {} attempts", attempts).into()
                            );
                        }
                        sleep(Duration::from_secs(5)).await;
                        continue;
                    }
                    _ => {
                        return Err(format!("Unknown operation status: {}", status.status).into());
                    }
                }
            }

            if attempts >= max_attempts {
                return Err(format!("Operation not found after {} attempts", attempts).into());
            }

            sleep(Duration::from_secs(5)).await;
        }
    }
}
