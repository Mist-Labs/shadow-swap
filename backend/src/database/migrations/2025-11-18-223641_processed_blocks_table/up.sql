-- Create processed_blocks table for tracking blockchain sync progress
CREATE TABLE IF NOT EXISTS processed_blocks (
    chain VARCHAR(20) PRIMARY KEY,
    block_number BIGINT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Insert initial values for both chains
INSERT INTO processed_blocks (chain, block_number, updated_at)
VALUES 
    ('starknet', 0, CURRENT_TIMESTAMP),
    ('zcash', 0, CURRENT_TIMESTAMP)
ON CONFLICT (chain) DO NOTHING;

-- Create trigger to auto-update updated_at
CREATE TRIGGER update_processed_blocks_updated_at
    BEFORE UPDATE ON processed_blocks
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();