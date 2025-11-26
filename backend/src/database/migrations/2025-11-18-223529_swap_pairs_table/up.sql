-- Create swap_pairs table with privacy parameters
CREATE TABLE IF NOT EXISTS swap_pairs (
    id VARCHAR(66) PRIMARY KEY,
    starknet_htlc_address VARCHAR(66),
    zcash_txid VARCHAR(64),
    initiator VARCHAR(255) NOT NULL,
    responder VARCHAR(255) NOT NULL,
    hash_lock VARCHAR(66) NOT NULL UNIQUE,
    secret VARCHAR(64),
    starknet_amount VARCHAR(78) NOT NULL,
    zcash_amount VARCHAR(78) NOT NULL,
    starknet_timelock BIGINT NOT NULL,
    zcash_timelock BIGINT NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'initiated',
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    -- Privacy parameters
    zcash_recipient VARCHAR(255),
    stealth_initiator VARCHAR(66),
    stealth_participant VARCHAR(66),
    token_address VARCHAR(66),
    amount_commitment VARCHAR(66),
    encrypted_data TEXT,
    ephemeral_pubkey VARCHAR(66),
    range_proof TEXT,
    bit_blinding_seed VARCHAR(66),
    blinding_factor VARCHAR(66)
);

-- Create indexes for efficient queries
CREATE INDEX idx_swap_pairs_hash_lock ON swap_pairs(hash_lock);
CREATE INDEX idx_swap_pairs_status ON swap_pairs(status);
CREATE INDEX idx_swap_pairs_created_at ON swap_pairs(created_at);
CREATE INDEX idx_swap_pairs_starknet_htlc ON swap_pairs(starknet_htlc_address);
CREATE INDEX idx_swap_pairs_zcash_txid ON swap_pairs(zcash_txid);

-- Create trigger to auto-update updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_swap_pairs_updated_at
    BEFORE UPDATE ON swap_pairs
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();