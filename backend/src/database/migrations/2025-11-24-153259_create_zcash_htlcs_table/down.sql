-- This file should undo anything in `up.sql`
DROP INDEX IF EXISTS zcash_htlcs_txid_idx;
DROP INDEX IF EXISTS zcash_htlcs_hash_lock_idx;

-- Drop the table
DROP TABLE zcash_htlcs;