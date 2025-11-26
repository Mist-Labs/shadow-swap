-- Your SQL goes here
CREATE TABLE indexer_checkpoints (
    chain VARCHAR NOT NULL PRIMARY KEY,
    last_block INTEGER NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);