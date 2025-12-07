use chrono::{DateTime, Utc};
use diesel::prelude::*;
use serde::{Deserialize, Serialize};

use crate::{
    merkle_tree::model::PoolType,
    models::schema::{htlc_events, processed_blocks, swap_pairs},
};

// ==================== Swap Pairs ====================

// Queryable struct for reading from database
#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = swap_pairs)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct DbSwapPair {
    pub id: String,
    pub starknet_htlc_nullifier: Option<String>,
    pub zcash_txid: Option<String>,
    pub initiator: String,
    pub responder: String,
    pub hash_lock: String,
    pub secret: Option<String>,
    pub starknet_amount: String,
    pub zcash_amount: String,
    pub starknet_timelock: i64,
    pub zcash_timelock: i64,
    pub status: String,
    pub notes: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    // Privacy parameters
    pub zcash_recipient: Option<String>,
    pub stealth_initiator: Option<String>,
    pub stealth_participant: Option<String>,
    pub token_address: Option<String>,
    pub amount_commitment: Option<String>,
    pub encrypted_data: Option<String>,
    pub ephemeral_pubkey: Option<String>,
    pub range_proof: Option<String>,
    pub bit_blinding_seed: Option<String>,
    pub blinding_factor: Option<String>,
}

// Insertable struct for creating new records
#[derive(Debug, Insertable)]
#[diesel(table_name = swap_pairs)]
pub struct NewSwapPair<'a> {
    pub id: &'a str,
    pub starknet_htlc_nullifier: Option<&'a str>,
    pub zcash_txid: Option<&'a str>,
    pub initiator: &'a str,
    pub responder: &'a str,
    pub hash_lock: &'a str,
    pub secret: Option<&'a str>,
    pub starknet_amount: &'a str,
    pub zcash_amount: &'a str,
    pub starknet_timelock: i64,
    pub zcash_timelock: i64,
    pub status: &'a str,
    pub notes: Option<&'a str>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    // Privacy parameters
    pub zcash_recipient: Option<&'a str>,
    pub stealth_initiator: Option<&'a str>,
    pub stealth_participant: Option<&'a str>,
    pub token_address: Option<&'a str>,
    pub amount_commitment: Option<&'a str>,
    pub encrypted_data: Option<&'a str>,
    pub ephemeral_pubkey: Option<&'a str>,
    pub range_proof: Option<&'a str>,
    pub bit_blinding_seed: Option<&'a str>,
    pub blinding_factor: Option<&'a str>,
}

// ==================== HTLC Events ====================

// Queryable struct for HTLC events
#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = htlc_events)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct DbHTLCEvent {
    pub id: i32,
    pub event_id: String,
    pub swap_id: Option<String>,
    pub event_type: String,
    pub event_data: serde_json::Value,
    pub chain: String,
    pub block_number: i64,
    pub transaction_hash: String,
    pub timestamp: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub in_merkle_tree: Option<bool>,
    pub merkle_index: Option<i32>,
    pub pool_type: Option<String>,
}

// Insertable struct for HTLC events
#[derive(Debug, Insertable)]
#[diesel(table_name = htlc_events)]
pub struct NewHTLCEvent<'a> {
    pub event_id: &'a str,
    pub swap_id: &'a str,
    pub event_type: &'a str,
    pub event_data: serde_json::Value,
    pub chain: &'a str,
    pub block_number: i64,
    pub transaction_hash: &'a str,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct MerkleDeposit {
    pub commitment: String,
    pub token_address: String,
    pub amount: String,
    pub pool_type: String,
}

#[derive(Queryable)]
pub struct DepositStatusQuery {
    pub in_merkle_tree: bool,
    pub merkle_index: Option<i32>,
    pub pool_type: String,
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = crate::models::schema::htlc_events)]
pub struct DbDepositStatus {
    pub in_merkle_tree: bool,
    pub merkle_index: Option<i32>,
    pub pool_type: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
pub enum HTLCState {
    Pending = 0,
    Redeemed = 1,
    Refunded = 2,
}

impl HTLCState {
    pub fn from_i16(value: i16) -> Self {
        match value {
            0 => HTLCState::Pending,
            1 => HTLCState::Redeemed,
            2 => HTLCState::Refunded,
            _ => HTLCState::Pending,
        }
    }
}

// ==================== Processed Blocks ====================

#[derive(Debug, Clone)]
pub struct PendingDeposit {
    pub commitment: String,
    pub token_address: String,
    pub pool_type: PoolType,
    pub transaction_hash: String,
    pub block_number: u64,
}

#[derive(Debug, Clone)]
pub struct DepositStatus {
    pub in_merkle_tree: bool,
    pub merkle_index: Option<u32>,
    pub pool_type: String,
}

// Queryable struct for processed blocks
#[derive(Debug, Clone, Queryable, Selectable)]
#[diesel(table_name = processed_blocks)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct ProcessedBlock {
    pub chain: String,
    pub block_number: i64,
    pub updated_at: DateTime<Utc>,
}

#[derive(Insertable)]
#[diesel(table_name = crate::models::schema::zcash_htlcs)]
pub struct NewZcashHTLC<'a> {
    pub txid: &'a str,
    pub hash_lock: &'a str,
    pub timelock: i64,
    pub recipient: &'a str,
    pub amount: f64,
    pub state: i16,
}

#[derive(Queryable, Selectable)]
#[diesel(table_name = crate::models::schema::zcash_htlcs)]
pub struct DbZcashHTLC {
    pub id: i32,
    pub txid: String,
    pub hash_lock: String,
    pub timelock: i64,
    pub recipient: String,
    pub amount: f64,
    pub state: i16,
    pub htlc_details: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Queryable, Selectable, Debug)]
#[diesel(table_name = crate::models::schema::indexer_checkpoints)]
#[diesel(check_for_backend(diesel::pg::Pg))]
pub struct IndexerCheckpoint {
    pub chain: String,
    pub last_block: i32,
    pub updated_at: DateTime<Utc>,
}

#[derive(Insertable)]
#[diesel(table_name = crate::models::schema::indexer_checkpoints)]
pub struct NewIndexerCheckpoint<'a> {
    pub chain: &'a str,
    pub last_block: i32,
    pub updated_at: DateTime<Utc>,
}

// ==================== Helper Structs ====================

/// Privacy parameters extracted from swap_pairs for HTLC operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SwapPrivacyParams {
    pub swap_id: String,
    pub initiator: String,
    pub participant: String,
    pub hash_lock: String,
    pub starknet_amount: String,
    pub zcash_amount: String,
    pub starknet_timelock: u64,
    pub zcash_timelock: u64,
    pub starknet_htlc_nullifier: Option<String>,
    // Privacy-specific fields
    pub zcash_recipient: Option<String>,
    pub stealth_initiator: Option<String>,
    pub stealth_participant: Option<String>,
    pub token_address: Option<String>,
    pub amount_commitment: Option<String>,
    pub encrypted_data: Option<String>,
    pub ephemeral_pubkey: Option<String>,
    pub range_proof: Option<String>,
    pub bit_blinding_seed: Option<String>,
    pub blinding_factor: Option<String>,
}

/// Statistics for coordinator monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoordinatorStats {
    pub total_swaps: u64,
    pub successful_swaps: u64,
    pub failed_swaps: u64,
    pub refunded_swaps: u64,
    pub pending_swaps: u64,
    pub critical_swaps: u64,
}

impl CoordinatorStats {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "total_swaps": self.total_swaps,
            "successful_swaps": self.successful_swaps,
            "failed_swaps": self.failed_swaps,
            "refunded_swaps": self.refunded_swaps,
            "pending_swaps": self.pending_swaps,
            "critical_swaps": self.critical_swaps,
            "success_rate": if self.total_swaps > 0 {
                (self.successful_swaps as f64 / self.total_swaps as f64) * 100.0
            } else {
                0.0
            },
        })
    }
}

// ==================== Conversion Functions ====================

impl From<DbSwapPair> for SwapPrivacyParams {
    fn from(db_swap: DbSwapPair) -> Self {
        Self {
            swap_id: db_swap.id,
            initiator: db_swap.initiator,
            participant: db_swap.responder,
            hash_lock: db_swap.hash_lock,
            starknet_amount: db_swap.starknet_amount,
            zcash_amount: db_swap.zcash_amount,
            starknet_timelock: db_swap.starknet_timelock as u64,
            zcash_timelock: db_swap.zcash_timelock as u64,
            starknet_htlc_nullifier: db_swap.starknet_htlc_nullifier,
            zcash_recipient: db_swap.zcash_recipient,
            stealth_initiator: db_swap.stealth_initiator,
            stealth_participant: db_swap.stealth_participant,
            token_address: db_swap.token_address,
            amount_commitment: db_swap.amount_commitment,
            encrypted_data: db_swap.encrypted_data,
            ephemeral_pubkey: db_swap.ephemeral_pubkey,
            range_proof: db_swap.range_proof,
            bit_blinding_seed: db_swap.bit_blinding_seed,
            blinding_factor: db_swap.blinding_factor,
        }
    }
}
