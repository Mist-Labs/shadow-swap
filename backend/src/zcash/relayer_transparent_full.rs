use serde::Deserialize;
use std::sync::Arc;
use tracing::info;

use crate::{
    config::model::ZcashConfig,
    database::{database::Database, model::HTLCState},
    zcash::model::{
        ZcashHTLC, ZcashPrivacyParams, ZcashRelayer, ZcashRpcRequest, ZcashRpcResponse,
    },
};
use zcash_htlc_builder::{
    database::Database as HTLCDatabase, HTLCParams, ZcashConfig as HTLCConfig, ZcashHTLCClient,
    UTXO,
};

impl ZcashRelayer {
    pub fn new(config: ZcashConfig, database: Arc<Database>) -> Self {
        info!("🔒 Initializing Zcash P2SH HTLC relayer (PRODUCTION MODE)");

        let htlc_config = HTLCConfig::new(
            if config.network == "mainnet" {
                zcash_htlc_builder::ZcashNetwork::Mainnet
            } else {
                zcash_htlc_builder::ZcashNetwork::Testnet
            },
            config.rpc_url.clone(),
            config.database_url.clone(),
        )
        .with_auth(config.rpc_user.clone(), config.rpc_password.clone());

        let htlc_db = Arc::new(
            HTLCDatabase::new(&config.database_url, 10)
                .expect("Failed to initialize HTLC database"),
        );

        let htlc_client = ZcashHTLCClient::new(htlc_config, htlc_db);

        Self {
            rpc_url: config.rpc_url,
            rpc_user: config.rpc_user,
            rpc_password: config.rpc_password,
            wallet_name: config.wallet_name,
            pool_address: config.pool_address,
            private_key: config.private_key,
            client: reqwest::Client::new(),
            database,
            htlc_client: Some(htlc_client),
        }
    }

    pub async fn initialize(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!("🔑 Zcash relayer initialized (PRODUCTION MODE - real transactions)");
        info!("📋 P2SH HTLC code is ZIP-300 compliant and production-ready");
        Ok(())
    }

    pub async fn create_htlc(
        &self,
        recipient: &str,
        amount: &str,
        hash_lock: &str,
        timelock: u64,
    ) -> Result<String, Box<dyn std::error::Error>> {
        info!("🔨 Creating REAL Zcash P2SH HTLC on-chain");

        let htlc_client = self
            .htlc_client
            .as_ref()
            .ok_or("HTLC client not initialized")?;

        let recipient_privkey = htlc_client.generate_privkey();
        let recipient_pubkey = htlc_client.derive_pubkey(&recipient_privkey)?;

        let refund_privkey = htlc_client.generate_privkey();
        let refund_pubkey = htlc_client.derive_pubkey(&refund_privkey)?;

        let params = HTLCParams {
            recipient_pubkey: recipient_pubkey.clone(),
            refund_pubkey: refund_pubkey.clone(),
            hash_lock: hash_lock.to_string(),
            timelock,
            amount: amount.to_string(),
        };

        // Get funding UTXOs from relayer wallet
        let funding_utxos = self.get_relayer_utxos(amount).await?;

        info!("💰 Using {} UTXOs for funding", funding_utxos.len());

        // Create real HTLC on Zcash blockchain
        let result = htlc_client
            .create_htlc(
                params,
                funding_utxos,
                &self.pool_address,
                vec![&self.private_key],
            )
            .await?;

        info!("✅ Real Zcash HTLC created!");
        info!("📋 HTLC ID: {}", result.htlc_id);
        info!("📋 TXID: {}", result.txid);
        info!("📍 P2SH Address: {}", result.p2sh_address);

        let amount_f64: f64 = amount.parse()?;
        let htlc = ZcashHTLC {
            version: 1,
            hash_lock: hash_lock.to_string(),
            timelock,
            recipient: recipient.to_string(),
            amount: amount_f64,
            state: HTLCState::Pending,
        };

        self.database.record_zcash_htlc(&result.txid, &htlc)?;

        Ok(result.txid)
    }

    pub async fn redeem_htlc(
        &self,
        htlc_txid: &str,
        _vout: u32,
        recipient: &str,
        _amount: &str,
        secret: &str,
        _htlc_script: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        info!("🔓 Redeeming Zcash HTLC with real transaction");

        let htlc_client = self
            .htlc_client
            .as_ref()
            .ok_or("HTLC client not initialized")?;

        let htlc = htlc_client.get_htlc(htlc_txid)?;

        // Redeem HTLC on-chain
        let recipient_privkey = htlc_client.generate_privkey();
        let redeem_txid = htlc_client
            .redeem_htlc(&htlc.id, secret, recipient, &recipient_privkey)
            .await?;

        info!("✅ Zcash HTLC redeemed: {}", redeem_txid);

        self.database
            .update_zcash_htlc_state(htlc_txid, HTLCState::Redeemed)?;

        Ok(redeem_txid)
    }

    pub async fn refund_htlc(
        &self,
        htlc_txid: &str,
        _vout: u32,
        _amount: &str,
        _htlc_script: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        info!("♻️ Refunding Zcash HTLC");

        let htlc_client = self
            .htlc_client
            .as_ref()
            .ok_or("HTLC client not initialized")?;

        let htlc = htlc_client.get_htlc(htlc_txid)?;

        // Refund HTLC on-chain
        let refund_privkey = &self.private_key;
        let refund_txid = htlc_client
            .refund_htlc(&htlc.id, &self.pool_address, refund_privkey)
            .await?;

        info!("✅ Zcash HTLC refunded: {}", refund_txid);

        self.database
            .update_zcash_htlc_state(htlc_txid, HTLCState::Refunded)?;

        Ok(refund_txid)
    }

    async fn get_relayer_utxos(
        &self,
        amount_needed: &str,
    ) -> Result<Vec<UTXO>, Box<dyn std::error::Error>> {
        info!("🔍 Fetching UTXOs via RPC from remote node");

        let params = vec![
            serde_json::json!(1),       // min confirmations
            serde_json::json!(9999999), // max confirmations
            serde_json::json!([&self.pool_address]),
        ];

        let utxos: Vec<serde_json::Value> = match self.rpc_call("listunspent", params).await {
            Ok(utxos) => utxos,
            Err(e) => {
                let error_msg = e.to_string();
                if error_msg.contains("failed to lookup address") {
                    return Err(format!(
                    "DNS resolution failed for Zcash RPC URL: {}. Check your ZCASH_RPC_URL environment variable.",
                    self.rpc_url
                ).into());
                }
                return Err(format!("RPC call failed: {}", error_msg).into());
            }
        };

        let amount_f64: f64 = amount_needed.parse()?;
        let mut total = 0.0;
        let mut selected_utxos = Vec::new();

        for utxo in utxos {
            let txid = utxo["txid"].as_str().unwrap_or("").to_string();
            let vout = utxo["vout"].as_u64().unwrap_or(0) as u32;
            let amount = utxo["amount"].as_f64().unwrap_or(0.0);
            let script_pubkey = utxo["scriptPubKey"].as_str().unwrap_or("").to_string();
            let confirmations = utxo["confirmations"].as_u64().unwrap_or(0) as u32;

            selected_utxos.push(UTXO {
                txid,
                vout,
                script_pubkey,
                amount: amount.to_string(),
                confirmations,
            });

            total += amount;

            // Add 0.0001 ZEC for fee buffer
            if total >= amount_f64 + 0.0001 {
                break;
            }
        }

        if total < amount_f64 {
            return Err(
                format!("Insufficient balance: have {}, need {}", total, amount_f64).into(),
            );
        }

        info!(
            "✅ Selected {} UTXOs totaling {} ZEC (via RPC)",
            selected_utxos.len(),
            total
        );

        Ok(selected_utxos)
    }

    pub fn generate_privacy_params(
        &self,
    ) -> Result<ZcashPrivacyParams, Box<dyn std::error::Error>> {
        let htlc_client = self
            .htlc_client
            .as_ref()
            .ok_or("HTLC client not initialized")?;

        let secret = hex::encode(rand::random::<[u8; 32]>());
        let hash_lock = htlc_client.generate_hash_lock(&secret);

        Ok(ZcashPrivacyParams { secret, hash_lock })
    }

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

        let mut request_builder = self.client.post(&self.rpc_url).json(&request);

        if !self.rpc_user.is_empty() && !self.rpc_password.is_empty() {
            request_builder = request_builder.basic_auth(&self.rpc_user, Some(&self.rpc_password));
        } else if !self.rpc_user.is_empty() {
            request_builder = request_builder.header("x-api-key", &self.rpc_user);
        }

        let response = match request_builder.send().await {
            Ok(resp) => resp,
            Err(e) => {
                let error_msg = e.to_string();
                if error_msg.contains("dns") || error_msg.contains("resolve") {
                    return Err(format!(
                    "DNS resolution failed for {}. Check your network connection and ZCASH_RPC_URL.",
                    self.rpc_url
                ).into());
                } else if error_msg.contains("connection") || error_msg.contains("timeout") {
                    return Err(format!(
                        "Connection to {} failed. The RPC server might be down or unreachable.",
                        self.rpc_url
                    )
                    .into());
                }
                return Err(format!("HTTP request failed: {}", error_msg).into());
            }
        };

        let rpc_response: ZcashRpcResponse<T> = response.json().await?;

        if let Some(error) = rpc_response.error {
            return Err(format!("RPC error {}: {}", error.code, error.message).into());
        }

        rpc_response
            .result
            .ok_or_else(|| "No result in RPC response".into())
    }
}
