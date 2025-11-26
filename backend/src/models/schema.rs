// @generated automatically by Diesel CLI.

diesel::table! {
    htlc_events (id) {
        id -> Int4,
        #[max_length = 66]
        event_id -> Varchar,
        #[max_length = 66]
        swap_id -> Varchar,
        #[max_length = 20]
        event_type -> Varchar,
        event_data -> Jsonb,
        #[max_length = 20]
        chain -> Varchar,
        block_number -> Int8,
        #[max_length = 66]
        transaction_hash -> Varchar,
        timestamp -> Timestamptz,
        created_at -> Timestamptz,
    }
}

diesel::table! {
    indexer_checkpoints (chain) {
        chain -> Varchar,
        last_block -> Int4,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    processed_blocks (chain) {
        #[max_length = 20]
        chain -> Varchar,
        block_number -> Int8,
        updated_at -> Timestamptz,
    }
}

diesel::table! {
    swap_pairs (id) {
        #[max_length = 66]
        id -> Varchar,
        #[max_length = 66]
        starknet_htlc_nullifier -> Nullable<Varchar>,
        #[max_length = 64]
        zcash_txid -> Nullable<Varchar>,
        #[max_length = 255]
        initiator -> Varchar,
        #[max_length = 255]
        responder -> Varchar,
        #[max_length = 66]
        hash_lock -> Varchar,
        #[max_length = 64]
        secret -> Nullable<Varchar>,
        #[max_length = 78]
        starknet_amount -> Varchar,
        #[max_length = 78]
        zcash_amount -> Varchar,
        starknet_timelock -> Int8,
        zcash_timelock -> Int8,
        #[max_length = 20]
        status -> Varchar,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
        notes -> Nullable<Text>,
        #[max_length = 255]
        zcash_recipient -> Nullable<Varchar>,
        #[max_length = 66]
        stealth_initiator -> Nullable<Varchar>,
        #[max_length = 66]
        stealth_participant -> Nullable<Varchar>,
        #[max_length = 66]
        token_address -> Nullable<Varchar>,
        #[max_length = 66]
        amount_commitment -> Nullable<Varchar>,
        encrypted_data -> Nullable<Text>,
        #[max_length = 66]
        ephemeral_pubkey -> Nullable<Varchar>,
        range_proof -> Nullable<Text>,
        #[max_length = 66]
        bit_blinding_seed -> Nullable<Varchar>,
        #[max_length = 66]
        blinding_factor -> Nullable<Varchar>,
    }
}

diesel::table! {
    zcash_htlcs (id) {
        id -> Int4,
        txid -> Varchar,
        hash_lock -> Varchar,
        timelock -> Int8,
        recipient -> Varchar,
        amount -> Float8,
        state -> Int2,
        created_at -> Timestamptz,
        updated_at -> Timestamptz,
    }
}

diesel::joinable!(htlc_events -> swap_pairs (swap_id));

diesel::allow_tables_to_appear_in_same_query!(
    htlc_events,
    indexer_checkpoints,
    processed_blocks,
    swap_pairs,
    zcash_htlcs,
);
