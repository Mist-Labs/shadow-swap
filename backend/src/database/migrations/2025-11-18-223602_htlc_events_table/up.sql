-- Create htlc_events table
CREATE TABLE IF NOT EXISTS htlc_events (
    id SERIAL PRIMARY KEY,
    event_id VARCHAR(66) NOT NULL UNIQUE,
    swap_id VARCHAR(66) NOT NULL,
    event_type VARCHAR(20) NOT NULL,
    event_data JSONB NOT NULL,
    chain VARCHAR(20) NOT NULL,
    block_number BIGINT NOT NULL,
    transaction_hash VARCHAR(66) NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Create foreign key to swap_pairs
ALTER TABLE htlc_events
    ADD CONSTRAINT fk_htlc_events_swap_id
    FOREIGN KEY (swap_id)
    REFERENCES swap_pairs(id)
    ON DELETE CASCADE;

-- Create indexes for efficient queries
CREATE INDEX idx_htlc_events_swap_id ON htlc_events(swap_id);
CREATE INDEX idx_htlc_events_chain ON htlc_events(chain);
CREATE INDEX idx_htlc_events_event_type ON htlc_events(event_type);
CREATE INDEX idx_htlc_events_block_number ON htlc_events(block_number);
CREATE INDEX idx_htlc_events_timestamp ON htlc_events(timestamp);
CREATE INDEX idx_htlc_events_created_at ON htlc_events(created_at);