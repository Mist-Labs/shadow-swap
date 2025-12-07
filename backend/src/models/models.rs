use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapPair {
    pub id: String,
    pub starknet_htlc_nullifier: Option<String>,
    pub zcash_txid: Option<String>,
    pub initiator: String,
    pub responder: String,
    pub hash_lock: String,
    pub secret: Option<String>,
    pub starknet_amount: String,
    pub zcash_amount: String,
    pub starknet_timelock: u64,
    pub zcash_timelock: u64,
    pub status: SwapStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SwapStatus {
    Initiated,
    Locked,
    Redeemed,
    Refunded,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HTLCEvent {
    pub event_id: String,
    pub swap_id: String,
    pub event_type: HTLCEventType,
    pub chain: String,
    pub block_number: u64,
    pub transaction_hash: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum HTLCEventType {
    Initiated {
        hash_lock: String,
        nullifier: Option<String>,
        pool_type: String,
        initiator: String,
        participant: String,
    },
    Redeemed {
        secret: String,
    },
    Refunded {
        pool_type: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Chain {
    Starknet,
    Zcash,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayTask {
    pub swap_id: String,
    pub action: RelayAction,
    pub target_chain: Chain,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RelayAction {
    InitiateHTLC {
        receiver: String,
        amount: String,
        hash_lock: String,
        timelock: u64,
    },
    RedeemHTLC {
        htlc_id: String,
        secret: String,
    },
    RefundHTLC {
        htlc_id: String,
    },
}

#[derive(Debug, Deserialize)]
pub struct InitiateSwapRequest {
    pub user_address: String,
    pub swap_direction: String, // "starknet_to_zcash" or "zcash_to_starknet"
    pub commitment: String,
    pub hash_lock: String, // SHA256 hash of secret
    pub starknet_amount: String,
    pub zcash_amount: String,
}

#[derive(Debug, Serialize)]
pub struct InitiateSwapResponse {
    pub success: bool,
    pub swap_id: String,
    pub message: String,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct IndexerEventRequest {
    pub event_type: String, // "htlc_created" | "htlc_redeemed" | "htlc_refunded"
    pub chain: String,      // "starknet" | "zcash"
    pub transaction_hash: String,
    pub timestamp: i64,
    pub pool_type: String,
    pub swap_id: Option<String>,
    pub commitment: Option<String>,
    pub nullifier: Option<String>, // For Starknet events
    pub hash_lock: Option<String>,
    pub secret: Option<String>, // For redemption events
    pub stealth_initiator: Option<String>,
    pub stealth_participant: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct IndexerEventResponse {
    pub success: bool,
    pub message: String,
    pub error: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PriceRequest {
    pub from_symbol: String,
    pub to_symbol: String,
    pub amount: Option<f64>,
}

#[derive(Debug, Serialize)]
pub struct PriceResponse {
    pub from_symbol: String,
    pub to_symbol: String,
    pub rate: f64,
    pub amount: Option<f64>,
    pub converted_amount: Option<f64>,
    pub timestamp: i64,
    pub sources: Vec<PriceSourceInfo>,
}

#[derive(Debug, Serialize)]
pub struct PriceSourceInfo {
    pub source: String,
    pub price: f64,
}

#[derive(Debug, Serialize)]
pub struct AllPricesResponse {
    pub strk_to_zec: f64,
    pub zec_to_strk: f64,
    pub strk_to_usd: f64,
    pub zec_to_usd: f64,
    pub timestamp: i64,
}

#[derive(Debug, Deserialize)]
pub struct ConvertRequest {
    pub from_symbol: String,
    pub to_symbol: String,
    pub amount: f64,
}

#[derive(Debug, Serialize)]
pub struct ConvertResponse {
    pub from_symbol: String,
    pub to_symbol: String,
    pub input_amount: f64,
    pub output_amount: f64,
    pub rate: f64,
    pub timestamp: i64,
}
