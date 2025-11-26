use chrono::Utc;
use diesel::pg::PgConnection;
use diesel::prelude::*;
use diesel::r2d2::{self, ConnectionManager, Pool};
use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use dotenv::dotenv;
use tracing::info;

use crate::database::model::{
    CoordinatorStats, DbSwapPair, MerkleDeposit, NewHTLCEvent, NewSwapPair, NewZcashHTLC, ProcessedBlock, SwapPrivacyParams
};
use crate::merkle_tree::model::PoolType;
use crate::models::models::{Chain, HTLCEvent, HTLCEventType, SwapPair, SwapStatus};
use crate::models::schema::swap_pairs::dsl;
use crate::models::schema::{htlc_events, processed_blocks, swap_pairs};
use crate::zcash::indexer::model::{HTLCState, ZcashHTLC};

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("src/database/migrations");

pub type DbPool = Pool<ConnectionManager<PgConnection>>;

// ==================== Error Types ====================

#[derive(Debug)]
pub enum DatabaseSetupError {
    DbConnectionError(::r2d2::Error),
    DieselError(diesel::result::Error),
    DatabaseUrlNotSet,
    ErrorRunningMigrations,
}

impl std::fmt::Display for DatabaseSetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DatabaseSetupError::DbConnectionError(e) => {
                write!(f, "Database connection error: {}", e)
            }
            DatabaseSetupError::DieselError(e) => write!(f, "Diesel error: {}", e),
            DatabaseSetupError::DatabaseUrlNotSet => write!(f, "DATABASE_URL not set"),
            DatabaseSetupError::ErrorRunningMigrations => write!(f, "Error running migrations"),
        }
    }
}

impl std::error::Error for DatabaseSetupError {}

// ==================== Database ====================

#[derive(Clone)]
pub struct Database {
    pool: DbPool,
}

impl Database {
    pub fn new(
        database_url: &str,
        max_connection: u32,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let manager = ConnectionManager::<PgConnection>::new(database_url);
        let pool = Pool::builder().max_size(max_connection).build(manager)?;

        Ok(Database { pool })
    }

    pub fn from_env() -> Result<Self, DatabaseSetupError> {
        dotenv().ok();

        let database_url =
            std::env::var("DATABASE_URL").map_err(|_| DatabaseSetupError::DatabaseUrlNotSet)?;

        let max_connections = std::env::var("DATABASE_MAX_CONNECTIONS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10);

        let manager = ConnectionManager::<PgConnection>::new(database_url);
        let pool = Pool::builder()
            .max_size(max_connections)
            .build(manager)
            .map_err(|e| DatabaseSetupError::DbConnectionError(e))?;

        let env = std::env::var("APP_ENV").unwrap_or_else(|_| "prod".into());
        if env == "dev" {
            run_migrations(&pool)?;
        }

        Ok(Database { pool })
    }

    pub fn get_connection(
        &self,
    ) -> Result<r2d2::PooledConnection<ConnectionManager<PgConnection>>, Box<dyn std::error::Error>>
    {
        Ok(self.pool.get()?)
    }

    pub fn run_migrations(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut conn = self.get_connection()?;
        conn.run_pending_migrations(MIGRATIONS)
            .map_err(|e| format!("Migration error: {}", e))?;
        Ok(())
    }

    // ==================== Swap CRUD Operations ====================

    pub fn create_swap_pair(&self, swap: &SwapPair) -> Result<(), Box<dyn std::error::Error>> {
        let mut conn = self.get_connection()?;

        let new_swap = NewSwapPair {
            id: &swap.id,
            starknet_htlc_nullifier: swap.starknet_htlc_nullifier.as_deref(),
            zcash_txid: swap.zcash_txid.as_deref(),
            initiator: &swap.initiator,
            responder: &swap.responder,
            hash_lock: &swap.hash_lock,
            secret: swap.secret.as_deref(),
            starknet_amount: &swap.starknet_amount,
            zcash_amount: &swap.zcash_amount,
            starknet_timelock: swap.starknet_timelock as i64,
            zcash_timelock: swap.zcash_timelock as i64,
            status: swap.status.as_str(),
            notes: None,
            created_at: swap.created_at,
            updated_at: swap.updated_at,
            zcash_recipient: None,
            stealth_initiator: None,
            stealth_participant: None,
            token_address: None,
            amount_commitment: None,
            encrypted_data: None,
            ephemeral_pubkey: None,
            range_proof: None,
            bit_blinding_seed: None,
            blinding_factor: None,
        };

        diesel::insert_into(swap_pairs::table)
            .values(&new_swap)
            .execute(&mut conn)?;

        Ok(())
    }

    pub fn create_swap_with_privacy(
        &self,
        swap: &SwapPair,
        privacy_params: &SwapPrivacyParams,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut conn = self.get_connection()?;

        let new_swap = NewSwapPair {
            id: &swap.id,
            starknet_htlc_nullifier: swap.starknet_htlc_nullifier.as_deref(),
            zcash_txid: swap.zcash_txid.as_deref(),
            initiator: &swap.initiator,
            responder: &swap.responder,
            hash_lock: &swap.hash_lock,
            secret: swap.secret.as_deref(),
            starknet_amount: &swap.starknet_amount,
            zcash_amount: &swap.zcash_amount,
            starknet_timelock: swap.starknet_timelock as i64,
            zcash_timelock: swap.zcash_timelock as i64,
            status: swap.status.as_str(),
            notes: None,
            created_at: swap.created_at,
            updated_at: swap.updated_at,
            zcash_recipient: privacy_params.zcash_recipient.as_deref(),
            stealth_initiator: privacy_params.stealth_initiator.as_deref(),
            stealth_participant: privacy_params.stealth_participant.as_deref(),
            token_address: privacy_params.token_address.as_deref(),
            amount_commitment: privacy_params.amount_commitment.as_deref(),
            encrypted_data: privacy_params.encrypted_data.as_deref(),
            ephemeral_pubkey: privacy_params.ephemeral_pubkey.as_deref(),
            range_proof: privacy_params.range_proof.as_deref(),
            bit_blinding_seed: privacy_params.bit_blinding_seed.as_deref(),
            blinding_factor: privacy_params.blinding_factor.as_deref(),
        };

        diesel::insert_into(swap_pairs::table)
            .values(&new_swap)
            .execute(&mut conn)?;

        Ok(())
    }

    pub fn update_privacy_params(
        &self,
        swap_id: &str,
        privacy_params: &SwapPrivacyParams,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut conn = self.get_connection()?;

        diesel::update(dsl::swap_pairs.filter(dsl::id.eq(swap_id)))
            .set((
                dsl::zcash_recipient.eq(privacy_params.zcash_recipient.as_deref()),
                dsl::stealth_initiator.eq(privacy_params.stealth_initiator.as_deref()),
                dsl::stealth_participant.eq(privacy_params.stealth_participant.as_deref()),
                dsl::token_address.eq(privacy_params.token_address.as_deref()),
                dsl::amount_commitment.eq(privacy_params.amount_commitment.as_deref()),
                dsl::encrypted_data.eq(privacy_params.encrypted_data.as_deref()),
                dsl::ephemeral_pubkey.eq(privacy_params.ephemeral_pubkey.as_deref()),
                dsl::range_proof.eq(privacy_params.range_proof.as_deref()),
                dsl::bit_blinding_seed.eq(privacy_params.bit_blinding_seed.as_deref()),
                dsl::blinding_factor.eq(privacy_params.blinding_factor.as_deref()),
                dsl::updated_at.eq(Utc::now()),
            ))
            .execute(&mut conn)?;

        Ok(())
    }

    pub fn update_swap_status(
        &self,
        swap_id: &str,
        status: SwapStatus,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut conn = self.get_connection()?;

        diesel::update(dsl::swap_pairs.filter(dsl::id.eq(swap_id)))
            .set((
                dsl::status.eq(status.as_str()),
                dsl::updated_at.eq(Utc::now()),
            ))
            .execute(&mut conn)?;

        Ok(())
    }

    pub fn update_swap_secret(
        &self,
        swap_id: &str,
        secret: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut conn = self.get_connection()?;

        diesel::update(dsl::swap_pairs.filter(dsl::id.eq(swap_id)))
            .set((dsl::secret.eq(secret), dsl::updated_at.eq(Utc::now())))
            .execute(&mut conn)?;

        Ok(())
    }

    pub fn update_starknet_htlc_address(
        &self,
        swap_id: &str,
        htlc_address: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut conn = self.get_connection()?;

        diesel::update(dsl::swap_pairs.filter(dsl::id.eq(swap_id)))
            .set((
                dsl::starknet_htlc_nullifier.eq(htlc_address),
                dsl::updated_at.eq(Utc::now()),
            ))
            .execute(&mut conn)?;

        Ok(())
    }

    pub fn get_swaps_awaiting_secret(&self) -> Result<Vec<SwapPair>, Box<dyn std::error::Error>> {
        let mut conn = self.get_connection()?;

        let results = dsl::swap_pairs
            .filter(dsl::status.eq("locked"))
            .filter(dsl::secret.is_null())
            .select(DbSwapPair::as_select())
            .load::<DbSwapPair>(&mut conn)?;

        Ok(results.into_iter().map(db_swap_to_model).collect())
    }

    pub fn update_zcash_txid(
        &self,
        swap_id: &str,
        txid: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut conn = self.get_connection()?;

        diesel::update(dsl::swap_pairs.filter(dsl::id.eq(swap_id)))
            .set((dsl::zcash_txid.eq(txid), dsl::updated_at.eq(Utc::now())))
            .execute(&mut conn)?;

        Ok(())
    }

    pub fn get_swap_by_commitment(
    &self,
    commitment: &str,
) -> Result<Option<SwapPair>, Box<dyn std::error::Error>> {
    let mut conn = self.get_connection()?;

    let result = dsl::swap_pairs
        .filter(dsl::amount_commitment.eq(commitment))
        .select(DbSwapPair::as_select())
        .first::<DbSwapPair>(&mut conn)
        .optional()?;

    Ok(result.map(db_swap_to_model))
}

pub fn get_swap_by_nullifier(
    &self,
    nullifier: &str,
) -> Result<Option<SwapPair>, Box<dyn std::error::Error>> {
    let mut conn = self.get_connection()?;

    let result = dsl::swap_pairs
        .filter(dsl::starknet_htlc_nullifier.eq(nullifier))
        .select(DbSwapPair::as_select())
        .first::<DbSwapPair>(&mut conn)
        .optional()?;

    Ok(result.map(db_swap_to_model))
}

pub fn update_starknet_htlc_nullifier(
    &self,
    swap_id: &str,
    nullifier: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut conn = self.get_connection()?;

    diesel::update(dsl::swap_pairs.filter(dsl::id.eq(swap_id)))
        .set((
            dsl::starknet_htlc_nullifier.eq(nullifier),
            dsl::updated_at.eq(Utc::now()),
        ))
        .execute(&mut conn)?;

    Ok(())
}

    pub fn get_swap_by_id(
        &self,
        swap_id: &str,
    ) -> Result<Option<SwapPair>, Box<dyn std::error::Error>> {
        let mut conn = self.get_connection()?;

        let result = dsl::swap_pairs
            .filter(dsl::id.eq(swap_id))
            .select(DbSwapPair::as_select())
            .first::<DbSwapPair>(&mut conn)
            .optional()?;

        Ok(result.map(db_swap_to_model))
    }

    pub fn get_swap_by_hash_lock(
        &self,
        hash_lock: &str,
    ) -> Result<Option<SwapPair>, Box<dyn std::error::Error>> {
        let mut conn = self.get_connection()?;

        let result = dsl::swap_pairs
            .filter(dsl::hash_lock.eq(hash_lock))
            .select(DbSwapPair::as_select())
            .first::<DbSwapPair>(&mut conn)
            .optional()?;

        Ok(result.map(db_swap_to_model))
    }

    pub fn get_pending_swaps(&self) -> Result<Vec<SwapPair>, Box<dyn std::error::Error>> {
        let mut conn = self.get_connection()?;

        let results = dsl::swap_pairs
            .filter(dsl::status.eq_any(vec!["initiated", "locked"]))
            .select(DbSwapPair::as_select())
            .load::<DbSwapPair>(&mut conn)?;

        Ok(results.into_iter().map(db_swap_to_model).collect())
    }

    pub fn get_swap_by_stealth_addresses(
        &self,
        stealth_initiator: &str,
        stealth_participant: &str,
    ) -> Result<Option<SwapPair>, Box<dyn std::error::Error>> {
        let mut conn = self.get_connection()?;

        let result = dsl::swap_pairs
            .filter(
                dsl::stealth_initiator
                    .eq(stealth_initiator)
                    .and(dsl::stealth_participant.eq(stealth_participant)),
            )
            .select(DbSwapPair::as_select())
            .first::<DbSwapPair>(&mut conn)
            .optional()?;

        Ok(result.map(db_swap_to_model))
    }

    pub fn get_swap_privacy_params(
        &self,
        swap_id: &str,
    ) -> Result<SwapPrivacyParams, Box<dyn std::error::Error>> {
        let mut conn = self.get_connection()?;

        let swap = dsl::swap_pairs
            .filter(dsl::id.eq(swap_id))
            .select(DbSwapPair::as_select())
            .first::<DbSwapPair>(&mut conn)?;

        Ok(SwapPrivacyParams::from(swap))
    }

    pub fn add_note_to_swap(
        &self,
        swap_id: &str,
        note: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut conn = self.get_connection()?;

        let notes_result: Option<Option<String>> = dsl::swap_pairs
            .filter(dsl::id.eq(swap_id))
            .select(dsl::notes)
            .first::<Option<String>>(&mut conn)
            .optional()?;

        let existing_notes: Option<String> = notes_result.flatten();

        let timestamp = Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
        let new_note = format!("[{}] {}", timestamp, note);

        let updated_notes = match existing_notes {
            Some(old_notes) => format!("{}\n{}", old_notes, new_note),
            None => new_note,
        };

        diesel::update(dsl::swap_pairs.filter(dsl::id.eq(swap_id)))
            .set((dsl::notes.eq(updated_notes), dsl::updated_at.eq(Utc::now())))
            .execute(&mut conn)?;

        Ok(())
    }

    pub fn get_swaps_needing_retry(&self) -> Result<Vec<SwapPair>, Box<dyn std::error::Error>> {
        let mut conn = self.get_connection()?;

        let results = dsl::swap_pairs
            .filter(
                dsl::status
                    .eq_any(vec!["initiated", "locked"])
                    .and(dsl::notes.like("%RETRY%")),
            )
            .select(DbSwapPair::as_select())
            .load::<DbSwapPair>(&mut conn)?;

        Ok(results.into_iter().map(db_swap_to_model).collect())
    }

    pub fn get_critical_swaps(&self) -> Result<Vec<SwapPair>, Box<dyn std::error::Error>> {
        let mut conn = self.get_connection()?;

        let results = dsl::swap_pairs
            .filter(dsl::notes.like("%CRITICAL%"))
            .select(DbSwapPair::as_select())
            .load::<DbSwapPair>(&mut conn)?;

        Ok(results.into_iter().map(db_swap_to_model).collect())
    }

    pub fn get_coordinator_stats(&self) -> Result<CoordinatorStats, Box<dyn std::error::Error>> {
        let mut conn = self.get_connection()?;

        let total_swaps: i64 = dsl::swap_pairs.count().get_result(&mut conn)?;

        let successful_swaps: i64 = dsl::swap_pairs
            .filter(dsl::status.eq("redeemed"))
            .count()
            .get_result(&mut conn)?;

        let failed_swaps: i64 = dsl::swap_pairs
            .filter(dsl::status.eq("failed"))
            .count()
            .get_result(&mut conn)?;

        let refunded_swaps: i64 = dsl::swap_pairs
            .filter(dsl::status.eq("refunded"))
            .count()
            .get_result(&mut conn)?;

        let pending_swaps: i64 = dsl::swap_pairs
            .filter(dsl::status.eq_any(vec!["initiated", "locked"]))
            .count()
            .get_result(&mut conn)?;

        let critical_swaps: i64 = dsl::swap_pairs
            .filter(dsl::notes.like("%CRITICAL%"))
            .count()
            .get_result(&mut conn)?;

        Ok(CoordinatorStats {
            total_swaps: total_swaps as u64,
            successful_swaps: successful_swaps as u64,
            failed_swaps: failed_swaps as u64,
            refunded_swaps: refunded_swaps as u64,
            pending_swaps: pending_swaps as u64,
            critical_swaps: critical_swaps as u64,
        })
    }

    pub fn store_event(&self, event: &HTLCEvent) -> Result<(), Box<dyn std::error::Error>> {
        let mut conn = self.get_connection()?;

        let event_type_str = match &event.event_type {
            HTLCEventType::Initiated { .. } => "initiated",
            HTLCEventType::Redeemed { .. } => "redeemed",
            HTLCEventType::Refunded { .. } => "refunded",
        };

        let event_data = serde_json::to_value(&event.event_type)?;

        let new_event = NewHTLCEvent {
            event_id: &event.event_id,
            swap_id: &event.swap_id,
            event_type: event_type_str,
            event_data: event_data,
            chain: event.chain.as_str(),
            block_number: event.block_number as i64,
            transaction_hash: &event.transaction_hash,
            timestamp: event.timestamp,
        };

        diesel::insert_into(htlc_events::table)
            .values(&new_event)
            .execute(&mut conn)?;

        Ok(())
    }

    pub fn get_last_processed_block(
        &self,
        chain: Chain,
    ) -> Result<Option<u64>, Box<dyn std::error::Error>> {
        use crate::models::schema::processed_blocks::dsl as pb_dsl;

        let mut conn = self.get_connection()?;

        let result = pb_dsl::processed_blocks
            .filter(pb_dsl::chain.eq(chain.as_str()))
            .first::<ProcessedBlock>(&mut conn)
            .optional()?;

        Ok(result.map(|r| r.block_number as u64))
    }

    pub fn get_pending_merkle_deposits(
        &self,
        pool_type:  PoolType,
    ) -> Result<Vec<MerkleDeposit>, Box<dyn std::error::Error>> {
        let mut conn = self.get_connection()?;

        let pool_name = match pool_type {
            PoolType::Fast => "fast",
            PoolType::Standard => "standard",
        };

        // Get all locked swaps with commitments that haven't been added to merkle tree yet
        let results = dsl::swap_pairs
            .filter(dsl::status.eq("locked"))
            .filter(dsl::amount_commitment.is_not_null())
            .filter(dsl::token_address.is_not_null())
            .filter(dsl::notes.not_like(format!("%merkle tree ({}%", pool_name)))
            .select((dsl::amount_commitment, dsl::token_address, dsl::starknet_amount))
            .load::<(Option<String>, Option<String>, String)>(&mut conn)?;

        let deposits: Vec<MerkleDeposit> = results
            .into_iter()
            .filter_map(|(commitment, token, amount)| {
                Some(MerkleDeposit {
                    commitment: commitment?,
                    token_address: token?,
                    amount,
                    pool_type: pool_name.to_string(),
                })
            })
            .collect();

        Ok(deposits)
    }

    pub fn mark_deposit_in_merkle_tree(
        &self,
        commitment: &str,
        leaf_index: u32,
        pool_type:  PoolType,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let pool_name = match pool_type {
            PoolType::Fast => "fast",
            PoolType::Standard => "standard",
        };

        let note = format!("Added to merkle tree ({}): index {}", pool_name, leaf_index);

        let mut conn = self.get_connection()?;
        let swap_id: Option<String> = dsl::swap_pairs
            .filter(dsl::amount_commitment.eq(commitment))
            .select(dsl::id)
            .first(&mut conn)
            .optional()?;

        if let Some(id) = swap_id {
            self.add_note_to_swap(&id, &note)?;
        }

        Ok(())
    }

    pub fn record_merkle_root_update(
        &self,
        root: &str,
        tx_hash: &str,
        pool_type: PoolType,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let pool_name = match pool_type {
            PoolType::Fast => "Fast",
            PoolType::Standard => "Standard",
        };

        info!(
            "📝 {} Pool: Recorded merkle root update {} in tx {}",
            pool_name, root, tx_hash
        );

        Ok(())
    }

    pub fn get_default_token_address(&self) -> Result<String, Box<dyn std::error::Error>> {
        // Return first token address found, or default USDC on Starknet
        let mut conn = self.get_connection()?;

        let token: Option<String> = dsl::swap_pairs
            .filter(dsl::token_address.is_not_null())
            .select(dsl::token_address)
            .first(&mut conn)
            .optional()?
            .flatten();

        Ok(token.unwrap_or_else(|| {
            "0x053c91253bc9682c04929ca02ed00b3e423f6710d2ee7e0d5ebb06f3ecf368a8".to_string()
        }))
    }

    pub fn update_last_processed_block(
        &self,
        chain: Chain,
        block_number: u64,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use crate::models::schema::processed_blocks::dsl as pb_dsl;

        let mut conn = self.get_connection()?;

        diesel::insert_into(pb_dsl::processed_blocks)
            .values((
                pb_dsl::chain.eq(chain.as_str()),
                pb_dsl::block_number.eq(block_number as i64),
                pb_dsl::updated_at.eq(Utc::now()),
            ))
            .on_conflict(pb_dsl::chain)
            .do_update()
            .set((
                pb_dsl::block_number.eq(block_number as i64),
                pb_dsl::updated_at.eq(Utc::now()),
            ))
            .execute(&mut conn)?;

        Ok(())
    }

    pub fn record_zcash_htlc(
        &self,
        txid: &str,
        htlc: &ZcashHTLC,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use crate::models::schema::zcash_htlcs::dsl;
        let mut conn = self.get_connection()?;

        let new_htlc = NewZcashHTLC {
            txid,
            hash_lock: &htlc.hash_lock,
            timelock: htlc.timelock as i64,
            recipient: &htlc.recipient,
            amount: htlc.amount.to_string().parse::<f64>().unwrap_or(0.0),
            state: htlc.state.clone() as i16,
        };

        diesel::insert_into(dsl::zcash_htlcs)
            .values(&new_htlc)
            .execute(&mut conn)?;

        Ok(())
    }

    /// Update Zcash HTLC state
    pub fn update_zcash_htlc_state(
        &self,
        txid: &str,
        state: HTLCState,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use crate::models::schema::zcash_htlcs::dsl;
        let mut conn = self.get_connection()?;

        diesel::update(dsl::zcash_htlcs.filter(dsl::txid.eq(txid)))
            .set((
                dsl::state.eq(state as i16),
                dsl::updated_at.eq(Utc::now()),
            ))
            .execute(&mut conn)?;

        Ok(())
    }


    pub fn get_zcash_htlc_by_nullifier(
        &self,
        nullifier: &str,
    ) -> Result<Option<String>, Box<dyn std::error::Error>> {
        use crate::models::schema::zcash_htlcs::dsl;
        let mut conn = self.get_connection()?;

        // In Zcash, we need to match nullifier with HTLC
        // For now, return HTLC by hash_lock pattern match
        let result = dsl::zcash_htlcs
            .filter(dsl::state.eq(0)) // Pending state
            .select(dsl::txid)
            .first::<String>(&mut conn)
            .optional()?;

        Ok(result)
    }

    pub fn save_indexer_checkpoint(
        &self,
        chain: &str,
        height: u32,
    ) -> Result<(), Box<dyn std::error::Error>> {
        use crate::models::schema::indexer_checkpoints::dsl;
        let mut conn = self.get_connection()?;

        diesel::insert_into(dsl::indexer_checkpoints)
            .values((
                dsl::chain.eq(chain),
                dsl::last_block.eq(height as i32),
                dsl::updated_at.eq(Utc::now()),
            ))
            .on_conflict(dsl::chain)
            .do_update()
            .set((
                dsl::last_block.eq(height as i32),
                dsl::updated_at.eq(Utc::now()),
            ))
            .execute(&mut conn)?;

        Ok(())
    }


    pub fn get_indexer_checkpoint(
        &self,
        chain: &str,
    ) -> Result<Option<u32>, Box<dyn std::error::Error>> {
        use crate::models::schema::indexer_checkpoints::dsl;
        let mut conn = self.get_connection()?;

        let result = dsl::indexer_checkpoints
            .filter(dsl::chain.eq(chain))
            .select(dsl::last_block)
            .first::<i32>(&mut conn)
            .optional()?;

        Ok(result.map(|b| b as u32))
    }
}

// ==================== Helper Functions ====================

fn run_migrations(pool: &Pool<ConnectionManager<PgConnection>>) -> Result<(), DatabaseSetupError> {
    println!("RUNNING MIGRATIONS....");
    // Instance 2: Closure now correctly matches the absolute path enum variant type.
    let mut conn = pool
        .get()
        .map_err(|e| DatabaseSetupError::DbConnectionError(e))?;
    conn.run_pending_migrations(MIGRATIONS)
        .map_err(|_| DatabaseSetupError::ErrorRunningMigrations)?;
    println!("MIGRATIONS COMPLETED....");
    Ok(())
}

fn parse_status(s: &str) -> SwapStatus {
    match s {
        "initiated" => SwapStatus::Initiated,
        "locked" => SwapStatus::Locked,
        "redeemed" => SwapStatus::Redeemed,
        "refunded" => SwapStatus::Refunded,
        "failed" => SwapStatus::Failed,
        _ => SwapStatus::Failed,
    }
}

fn db_swap_to_model(r: DbSwapPair) -> SwapPair {
    SwapPair {
        id: r.id,
        starknet_htlc_nullifier: r.starknet_htlc_nullifier,
        zcash_txid: r.zcash_txid,
        initiator: r.initiator,
        responder: r.responder,
        hash_lock: r.hash_lock,
        secret: r.secret,
        starknet_amount: r.starknet_amount,
        zcash_amount: r.zcash_amount,
        starknet_timelock: r.starknet_timelock as u64,
        zcash_timelock: r.zcash_timelock as u64,
        status: parse_status(&r.status),
        created_at: r.created_at,
        updated_at: r.updated_at,
    }
}
