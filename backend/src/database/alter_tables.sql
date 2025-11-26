
\echo 'Starting database alterations...'

\echo '1. Altering swap_pairs table...'

ALTER TABLE swap_pairs 
    ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC',
    ALTER COLUMN updated_at TYPE TIMESTAMPTZ USING updated_at AT TIME ZONE 'UTC';

ALTER TABLE swap_pairs 
    ADD COLUMN IF NOT EXISTS notes TEXT;


ALTER TABLE swap_pairs 
    ADD COLUMN IF NOT EXISTS zcash_recipient VARCHAR(255),
    ADD COLUMN IF NOT EXISTS stealth_initiator VARCHAR(66),
    ADD COLUMN IF NOT EXISTS stealth_participant VARCHAR(66),
    ADD COLUMN IF NOT EXISTS token_address VARCHAR(66),
    ADD COLUMN IF NOT EXISTS amount_commitment VARCHAR(66),
    ADD COLUMN IF NOT EXISTS encrypted_data TEXT,
    ADD COLUMN IF NOT EXISTS ephemeral_pubkey VARCHAR(66),
    ADD COLUMN IF NOT EXISTS range_proof TEXT,
    ADD COLUMN IF NOT EXISTS bit_blinding_seed VARCHAR(66),
    ADD COLUMN IF NOT EXISTS blinding_factor VARCHAR(66);


CREATE INDEX IF NOT EXISTS idx_swap_pairs_starknet_htlc ON swap_pairs(starknet_htlc_address);
CREATE INDEX IF NOT EXISTS idx_swap_pairs_zcash_txid ON swap_pairs(zcash_txid);


CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';


DROP TRIGGER IF EXISTS update_swap_pairs_updated_at ON swap_pairs;
CREATE TRIGGER update_swap_pairs_updated_at
    BEFORE UPDATE ON swap_pairs
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

\echo '2. Altering htlc_events table...'


ALTER TABLE htlc_events 
    ALTER COLUMN timestamp TYPE TIMESTAMPTZ USING timestamp AT TIME ZONE 'UTC',
    ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';


CREATE INDEX IF NOT EXISTS idx_htlc_events_swap_id ON htlc_events(swap_id);
CREATE INDEX IF NOT EXISTS idx_htlc_events_chain ON htlc_events(chain);
CREATE INDEX IF NOT EXISTS idx_htlc_events_event_type ON htlc_events(event_type);
CREATE INDEX IF NOT EXISTS idx_htlc_events_block_number ON htlc_events(block_number);
CREATE INDEX IF NOT EXISTS idx_htlc_events_timestamp ON htlc_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_htlc_events_created_at ON htlc_events(created_at);

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint 
        WHERE conname = 'fk_htlc_events_swap_id'
    ) THEN
        ALTER TABLE htlc_events
            ADD CONSTRAINT fk_htlc_events_swap_id
            FOREIGN KEY (swap_id)
            REFERENCES swap_pairs(id)
            ON DELETE CASCADE;
    END IF;
END $$;

\echo '3. Altering processed_blocks table...'


ALTER TABLE processed_blocks 
    ALTER COLUMN updated_at TYPE TIMESTAMPTZ USING updated_at AT TIME ZONE 'UTC';


DROP TRIGGER IF EXISTS update_processed_blocks_updated_at ON processed_blocks;
CREATE TRIGGER update_processed_blocks_updated_at
    BEFORE UPDATE ON processed_blocks
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

\echo 'All alterations completed successfully!'