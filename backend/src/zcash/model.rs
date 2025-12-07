use std::sync::Arc;

use serde::{Deserialize, Serialize};
use zcash_htlc_builder::ZcashHTLCClient;
use zcash_transparent::bundle::{OutPoint, TxOut};

use crate::database::{database::Database, model::HTLCState};

#[derive(Debug, Clone)]
pub struct ZcashPrivacyParams {
    pub secret: String,
    pub hash_lock: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZcashRpcRequest {
    pub jsonrpc: String,
    pub id: String,
    pub method: String,
    pub params: Vec<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ZcashRpcResponse<T> {
    pub jsonrpc: String,
    pub id: String,
    pub result: Option<T>,
    pub error: Option<ZcashRpcError>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ZcashRpcError {
    pub code: i32,
    pub message: String,
}

pub struct ZcashRelayer {
    pub rpc_url: String,
    pub rpc_user: String,
    pub rpc_password: String,
    pub wallet_name: String,
    pub pool_address: String,
    pub private_key: String,
    pub client: reqwest::Client,
    pub database: Arc<Database>,
    pub htlc_client: Option<ZcashHTLCClient>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZcashHTLC {
    pub version: u8,
    pub hash_lock: String,
    pub timelock: u64,
    pub recipient: String,
    pub amount: f64,
    pub state: HTLCState,
}

#[derive(Debug)]
pub struct Utxo {
    pub outpoint: OutPoint,
    pub txout: TxOut,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZcashHTLCDetails {
    pub htlc_script: String,
    pub p2sh_address: String,
    pub recipient_pubkey_hash: String,
    pub refund_pubkey_hash: String,
    pub vout: u32,
}
