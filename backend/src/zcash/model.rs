use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::database::database::Database;

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
    pub client: reqwest::Client,
    pub database: Arc<Database>,
}