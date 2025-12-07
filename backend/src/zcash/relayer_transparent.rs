use std::sync::Arc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::info;

use crate::{
    config::model::ZcashConfig,
    database::{database::Database, model::HTLCState},
    zcash::model::{
        ZcashHTLC, ZcashPrivacyParams, ZcashRelayer, 
        ZcashRpcRequest, ZcashRpcResponse, ZcashHTLCDetails
    },
};

impl ZcashRelayer {
    pub fn new(config: ZcashConfig, database: Arc<Database>) -> Self {
        info!("🔒 Initializing Zcash P2SH HTLC relayer");

        Self {
            rpc_url: config.rpc_url,
            rpc_user: config.rpc_user,
            rpc_password: config.rpc_password,
            wallet_name: config.wallet_name,
            pool_address: config.pool_address,
            private_key: config.private_key,
            client: reqwest::Client::new(),
            database,
        }
    }

    pub async fn initialize(&self) -> Result<(), Box<dyn std::error::Error>> {
        info!("🔑 Ensuring private key is in zcashd wallet");
        
        let params = vec![
            serde_json::json!(self.private_key),
            serde_json::json!("shadow_swap_pool"),
            serde_json::json!(false),
        ];
        
        match self.rpc_call::<serde_json::Value>("importprivkey", params).await {
            Ok(_) => {
                info!("✅ Private key imported successfully");
            }
            Err(e) => {
                let err_msg = e.to_string().to_lowercase();
                if err_msg.contains("already") || err_msg.contains("duplicate") {
                    info!("✅ Private key already in wallet");
                } else {
                    return Err(e);
                }
            }
        }
        
        Ok(())
    }

    pub fn generate_privacy_params(
        &self,
        zcash_address: &str,
        amount: &str,
        timestamp: i64,
    ) -> Result<ZcashPrivacyParams, Box<dyn std::error::Error>> {
        let seed = format!("{}:{}:{}", zcash_address, amount, timestamp);

        let mut hasher = Sha256::new();
        hasher.update(seed.as_bytes());
        hasher.update(b":secret");
        let secret = hex::encode(hasher.finalize());

        let mut hasher = Sha256::new();
        hasher.update(secret.as_bytes());
        let hash_lock = hex::encode(hasher.finalize());

        Ok(ZcashPrivacyParams { secret, hash_lock })
    }

    pub async fn create_htlc(
        &self,
        recipient: &str,
        amount: &str,
        hash_lock: &str,
        timelock: u64,
    ) -> Result<String, Box<dyn std::error::Error>> {
        info!("🔨 Creating Zcash P2SH HTLC with on-chain enforcement");

        let amount_f64: f64 = amount.parse()?;
        
        let recipient_pubkey_hash = self.get_pubkey_hash(recipient).await?;
        let refund_pubkey_hash = self.get_pubkey_hash(&self.pool_address).await?;
        
        let htlc_script = self.create_htlc_script(
            hash_lock,
            &recipient_pubkey_hash,
            timelock,
            &refund_pubkey_hash,
        )?;
        
        let p2sh_address = self.create_p2sh_address(&htlc_script).await?;
        
        info!("📝 HTLC P2SH address: {}", p2sh_address);
        
        let txid = self.send_to_address(&p2sh_address, amount_f64).await?;
        
        let htlc = ZcashHTLC {
            version: 1,
            hash_lock: hash_lock.to_string(),
            timelock,
            recipient: recipient.to_string(),
            amount: amount_f64,
            state: HTLCState::Pending,
        };
        
        let htlc_details = ZcashHTLCDetails {
            htlc_script: htlc_script.clone(),
            p2sh_address: p2sh_address.clone(),
            recipient_pubkey_hash,
            refund_pubkey_hash,
            vout: 0,
        };
        
        self.database
            .record_zcash_htlc(&txid, &htlc)
            .map_err(|e| format!("Database error: {}", e))?;
        
        self.database
            .store_zcash_htlc_details(&txid, &htlc_details)
            .map_err(|e| format!("Failed to store HTLC details: {}", e))?;
        
        info!("✅ Zcash HTLC created: {} (P2SH: {})", txid, p2sh_address);
        Ok(txid)
    }

    fn create_htlc_script(
        &self,
        hash_lock: &str,
        recipient_pubkey_hash: &str,
        timelock: u64,
        refund_pubkey_hash: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let hash_bytes = hex::decode(hash_lock.trim_start_matches("0x"))?;
        let recipient_hash_bytes = hex::decode(recipient_pubkey_hash)?;
        let refund_hash_bytes = hex::decode(refund_pubkey_hash)?;
        
        let script = format!(
            "OP_IF \
                OP_SHA256 {} OP_EQUALVERIFY \
                OP_DUP OP_HASH160 {} \
            OP_ELSE \
                {} OP_CHECKLOCKTIMEVERIFY OP_DROP \
                OP_DUP OP_HASH160 {} \
            OP_ENDIF \
            OP_EQUALVERIFY OP_CHECKSIG",
            hex::encode(&hash_bytes),
            hex::encode(&recipient_hash_bytes),
            timelock,
            hex::encode(&refund_hash_bytes)
        );
        
        Ok(script)
    }

    async fn create_p2sh_address(&self, script: &str) -> Result<String, Box<dyn std::error::Error>> {
        #[derive(Deserialize)]
        struct DecodeScriptResponse {
            address: String,
        }
        
        let params = vec![serde_json::json!(script)];
        let response: DecodeScriptResponse = self.rpc_call("decodescript", params).await?;
        
        Ok(response.address)
    }

    async fn get_pubkey_hash(&self, address: &str) -> Result<String, Box<dyn std::error::Error>> {
        #[derive(Deserialize)]
        struct ValidateAddressResponse {
            #[serde(rename = "scriptPubKey")]
            script_pubkey: String,
        }
        
        let params = vec![serde_json::json!(address)];
        let response: ValidateAddressResponse = self.rpc_call("validateaddress", params).await?;
        
        let script_bytes = hex::decode(&response.script_pubkey)?;
        if script_bytes.len() >= 25 && script_bytes[0] == 0x76 && script_bytes[1] == 0xa9 {
            let pubkey_hash = &script_bytes[3..23];
            Ok(hex::encode(pubkey_hash))
        } else {
            Err("Invalid address script".into())
        }
    }

    pub async fn redeem_htlc(
        &self,
        htlc_txid: &str,
        vout: u32,
        recipient: &str,
        amount: &str,
        secret: &str,
        htlc_script: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        info!("🔓 Redeeming Zcash HTLC with secret revelation");

        let htlc = self.database
            .get_zcash_htlc_by_txid(htlc_txid)
            .map_err(|e| format!("HTLC not found: {}", e))?;
        
        htlc.can_redeem(secret)
            .map_err(|e| format!("Cannot redeem: {}", e))?;
        
        let amount_f64: f64 = amount.parse()?;
        
        let unsigned_tx = self.create_redeem_transaction(
            htlc_txid,
            vout,
            recipient,
            amount_f64,
        ).await?;
        
        let signed_tx = self.sign_htlc_redeem(
            &unsigned_tx,
            secret,
            htlc_script,
            vout,
        ).await?;
        
        let txid = self.broadcast_transaction(&signed_tx).await?;
        
        self.database
            .update_zcash_htlc_state(htlc_txid, HTLCState::Redeemed)
            .map_err(|e| format!("Database error: {}", e))?;
        
        info!("✅ Zcash HTLC redeemed: {}", txid);
        Ok(txid)
    }

    async fn create_redeem_transaction(
        &self,
        htlc_txid: &str,
        vout: u32,
        recipient: &str,
        amount: f64,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let inputs = vec![
            serde_json::json!({
                "txid": htlc_txid,
                "vout": vout
            })
        ];
        
        let outputs = serde_json::json!({
            recipient: amount - 0.0001
        });
        
        let params = vec![
            serde_json::json!(inputs),
            serde_json::json!(outputs),
        ];
        
        let raw_tx: String = self.rpc_call("createrawtransaction", params).await?;
        Ok(raw_tx)
    }

    async fn sign_htlc_redeem(
        &self,
        unsigned_tx: &str,
        secret: &str,
        htlc_script: &str,
        input_index: u32,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let redeem_script = format!(
            "{} OP_TRUE {}",
            hex::encode(secret.as_bytes()),
            htlc_script
        );
        
        let params = vec![
            serde_json::json!(unsigned_tx),
            serde_json::json!([{
                "txid": "placeholder",
                "vout": input_index,
                "scriptPubKey": htlc_script,
                "redeemScript": redeem_script,
            }]),
            serde_json::json!([self.private_key]),
        ];
        
        #[derive(Deserialize)]
        struct SignResponse {
            hex: String,
        }
        
        let response: SignResponse = self.rpc_call("signrawtransactionwithkey", params).await?;
        Ok(response.hex)
    }

    pub async fn refund_htlc(
        &self,
        htlc_txid: &str,
        vout: u32,
        amount: &str,
        htlc_script: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        info!("♻️ Refunding expired Zcash HTLC");

        let htlc = self.database
            .get_zcash_htlc_by_txid(htlc_txid)
            .map_err(|e| format!("HTLC not found: {}", e))?;
        
        htlc.can_refund()
            .map_err(|e| format!("Cannot refund: {}", e))?;
        
        let amount_f64: f64 = amount.parse()?;
        
        let unsigned_tx = self.create_redeem_transaction(
            htlc_txid,
            vout,
            &self.pool_address,
            amount_f64,
        ).await?;
        
        let signed_tx = self.sign_htlc_refund(
            &unsigned_tx,
            htlc_script,
            vout,
            htlc.timelock,
        ).await?;
        
        let txid = self.broadcast_transaction(&signed_tx).await?;
        
        self.database
            .update_zcash_htlc_state(htlc_txid, HTLCState::Refunded)
            .map_err(|e| format!("Database error: {}", e))?;
        
        info!("✅ Zcash HTLC refunded: {}", txid);
        Ok(txid)
    }

    async fn sign_htlc_refund(
        &self,
        unsigned_tx: &str,
        htlc_script: &str,
        input_index: u32,
        timelock: u64,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let refund_script = format!(
            "OP_FALSE {}",
            htlc_script
        );
        
        let params = vec![
            serde_json::json!(unsigned_tx),
            serde_json::json!([{
                "txid": "placeholder",
                "vout": input_index,
                "scriptPubKey": htlc_script,
                "redeemScript": refund_script,
                "sequence": 0xfffffffeu32,
            }]),
            serde_json::json!([self.private_key]),
        ];
        
        #[derive(Deserialize)]
        struct SignResponse {
            hex: String,
        }
        
        let response: SignResponse = self.rpc_call("signrawtransactionwithkey", params).await?;
        Ok(response.hex)
    }

    async fn send_to_address(
        &self,
        to_address: &str,
        amount: f64,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let params = vec![
            serde_json::json!(to_address),
            serde_json::json!(amount),
        ];
        
        let txid: String = self.rpc_call("sendtoaddress", params).await?;
        Ok(txid)
    }

    async fn broadcast_transaction(&self, raw_tx_hex: &str) -> Result<String, Box<dyn std::error::Error>> {
        let params = vec![serde_json::json!(raw_tx_hex)];
        let txid: String = self.rpc_call("sendrawtransaction", params).await?;
        Ok(txid)
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

        let mut request_builder = self
            .client
            .post(&self.rpc_url)
            .json(&request);

        if !self.rpc_user.is_empty() && !self.rpc_password.is_empty() {
            request_builder = request_builder.basic_auth(&self.rpc_user, Some(&self.rpc_password));
        } else if !self.rpc_user.is_empty() {
            request_builder = request_builder.header("x-api-key", &self.rpc_user);
        }

        let response = request_builder.send().await?;
        let rpc_response: ZcashRpcResponse<T> = response.json().await?;

        if let Some(error) = rpc_response.error {
            return Err(format!("RPC error {}: {}", error.code, error.message).into());
        }

        rpc_response
            .result
            .ok_or_else(|| "No result in RPC response".into())
    }

    pub async fn get_balance(&self) -> Result<f64, Box<dyn std::error::Error>> {
        let balance: f64 = self.rpc_call("getbalance", vec![]).await?;
        Ok(balance)
    }

    pub async fn get_transaction(&self, txid: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
        let params = vec![serde_json::json!(txid), serde_json::json!(true)];
        let tx: serde_json::Value = self.rpc_call("getrawtransaction", params).await?;
        Ok(tx)
    }
}