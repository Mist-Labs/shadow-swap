use std::{collections::HashSet, sync::Arc};

use reqwest::Client;
use serde::{Deserialize, Serialize};

use crate::{database::database::Database, zcash::model::ZcashRelayer};


#[derive(Debug, Clone, Serialize)]
pub struct IndexerEventPayload {
    pub event_type: String,
    pub chain: String,
    pub transaction_hash: String,
    pub commitment: Option<String>,
    pub hash_lock: Option<String>,
    pub nullifier: Option<String>,
    pub secret: Option<String>,
    pub amount: Option<String>,
    pub timestamp: u64,
}

#[derive(Debug, Deserialize)]
pub struct ZcashTransaction {
    pub txid: String,
    pub confirmations: u32,
    pub time: u64,
    pub vjoinsplit: Option<Vec<serde_json::Value>>,
    pub vShieldedOutput: Option<Vec<ShieldedOutput>>,
    pub vShieldedSpend: Option<Vec<ShieldedSpend>>,
}

#[derive(Debug, Deserialize)]
pub struct ShieldedOutput {
    pub cv: String,
    pub cmu: String,
    pub ephemeralKey: String,
    pub proof: String,
    pub encCiphertext: String,
    pub outCiphertext: String,
}

#[derive(Debug, Deserialize)]
pub struct ShieldedSpend {
    pub cv: String,
    pub anchor: String,
    pub nullifier: String,
    pub rk: String,
    pub proof: String,
    pub spendAuthSig: String,
}

#[derive(Debug, Deserialize)]
pub struct BlockInfo {
    pub hash: String,
    pub height: u32,
    pub tx: Vec<String>,
    pub time: u64,
}

pub struct ZcashIndexer {
    pub relayer: Arc<ZcashRelayer>,
    pub database: Arc<Database>,
    pub http_client: Client,
    pub relayer_api_url: String,
    pub hmac_secret: String,
    pub monitored_addresses: HashSet<String>,
    pub last_processed_block: u32,
    pub min_confirmations: u32,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum HTLCState {
    Pending = 0,
    Redeemed = 1,
    Refunded = 2,
}
