use std::sync::Arc;

use actix_web::{web, HttpRequest, HttpResponse, Responder};
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::Sha256;
use tracing::{error, info};

use crate::{
    merkle_tree::model::PoolType,
    models::models::{
        HTLCEvent, HTLCEventType, IndexerEventRequest, IndexerEventResponse, SwapStatus,
    },
    pricefeed::pricefeed::PriceCache,
    AppState,
};

type HmacSha256 = Hmac<Sha256>;

pub async fn handle_deposit_event(
    app_state: &web::Data<AppState>,
    request: &IndexerEventRequest,
) -> HttpResponse {
    let commitment = match &request.commitment {
        Some(c) => c,
        None => {
            return HttpResponse::BadRequest().json(IndexerEventResponse {
                success: false,
                message: "Deposit event missing commitment".to_string(),
                error: None,
            });
        }
    };

    // Parse pool_type directly from event (emitted by contract as felt252: 0 or 1)
    let pool_type = match request.pool_type.as_str() {
        "0" | "fast" | "Fast" => PoolType::Fast,
        "1" | "standard" | "Standard" => PoolType::Standard,
        _ => {
            return HttpResponse::BadRequest().json(IndexerEventResponse {
                success: false,
                message: format!("Invalid pool_type: {}", request.pool_type),
                error: None,
            });
        }
    };

    info!(
        "💰 Processing deposit | Pool: {:?} | Commitment: {}",
        pool_type,
        &commitment[..8]
    );

    if let Err(e) = app_state.database.insert_deposit_event(
        commitment,
        pool_type,
        &request.transaction_hash,
        0,
        request.timestamp,
    ) {
        error!("Failed to insert deposit event: {}", e);
        return HttpResponse::InternalServerError().json(IndexerEventResponse {
            success: false,
            message: "Failed to store deposit event".to_string(),
            error: Some(e.to_string()),
        });
    }

    info!(
        "✅ Deposit event inserted successfully for {:?} pool",
        pool_type
    );

    let token_address = match request.chain.as_str() {
        "starknet" => app_state.config.starknet.token_address.clone(),
        "zcash" => app_state.config.zcash.token_address.clone(),
        _ => {
            return HttpResponse::BadRequest().json(IndexerEventResponse {
                success: false,
                message: format!("Unsupported chain: {}", request.chain),
                error: None,
            });
        }
    };

    match app_state
        .merkle_tree_manager
        .add_commitment_immediately(commitment, &token_address, pool_type)
        .await
    {
        Ok(index) => {
            info!(
                "✅ Commitment added to merkle tree | Index: {} | Pool: {:?}",
                index, pool_type
            );

            if let Err(e) = app_state.database.record_deposit(
                commitment,
                pool_type,
                &request.transaction_hash,
                Some(index),
            ) {
                error!("Failed to record deposit with index: {}", e);
            }

            HttpResponse::Ok().json(IndexerEventResponse {
                success: true,
                message: format!("Deposit processed for {:?} pool, ready for swap", pool_type),
                error: None,
            })
        }
        Err(e) => {
            error!("Failed to add commitment to merkle tree: {}", e);
            HttpResponse::InternalServerError().json(IndexerEventResponse {
                success: false,
                message: "Failed to process deposit in merkle tree".to_string(),
                error: Some(e.to_string()),
            })
        }
    }
}

pub async fn handle_redemption_event(
    app_state: &web::Data<AppState>,
    request: &IndexerEventRequest,
) -> HttpResponse {
    info!("🔓 Redemption event received on chain: {}", request.chain);

    let secret = match &request.secret {
        Some(s) => s,
        None => {
            return HttpResponse::BadRequest().json(IndexerEventResponse {
                success: false,
                message: "Redemption event missing secret".to_string(),
                error: None,
            });
        }
    };

    let swap = if let Some(nullifier) = &request.nullifier {
        match app_state.database.get_swap_by_nullifier(nullifier) {
            Ok(Some(swap)) => swap,
            Ok(None) => {
                return HttpResponse::NotFound().json(IndexerEventResponse {
                    success: false,
                    message: "Swap not found for nullifier".to_string(),
                    error: Some(format!("No swap found for nullifier: {}", nullifier)),
                });
            }
            Err(e) => {
                error!("Database error looking up swap by nullifier: {}", e);
                return HttpResponse::InternalServerError().json(IndexerEventResponse {
                    success: false,
                    message: "Failed to lookup swap".to_string(),
                    error: Some(e.to_string()),
                });
            }
        }
    } else if let Some(commitment) = &request.commitment {
        match app_state.database.get_swap_by_commitment(commitment) {
            Ok(Some(swap)) => swap,
            Ok(None) => {
                return HttpResponse::NotFound().json(IndexerEventResponse {
                    success: false,
                    message: "Swap not found for commitment".to_string(),
                    error: Some(format!("No swap found for commitment: {}", commitment)),
                });
            }
            Err(e) => {
                error!("Database error looking up swap by commitment: {}", e);
                return HttpResponse::InternalServerError().json(IndexerEventResponse {
                    success: false,
                    message: "Failed to lookup swap".to_string(),
                    error: Some(e.to_string()),
                });
            }
        }
    } else if let Some(hash_lock) = &request.hash_lock {
        match app_state.database.get_swap_by_hash_lock(hash_lock) {
            Ok(Some(swap)) => swap,
            Ok(None) => {
                return HttpResponse::NotFound().json(IndexerEventResponse {
                    success: false,
                    message: "Swap not found for hash_lock".to_string(),
                    error: Some(format!("No swap found for hash_lock: {}", hash_lock)),
                });
            }
            Err(e) => {
                error!("Database error looking up swap by hash_lock: {}", e);
                return HttpResponse::InternalServerError().json(IndexerEventResponse {
                    success: false,
                    message: "Failed to lookup swap".to_string(),
                    error: Some(e.to_string()),
                });
            }
        }
    } else {
        return HttpResponse::BadRequest().json(IndexerEventResponse {
            success: false,
            message: "Must provide nullifier, commitment, or hash_lock".to_string(),
            error: None,
        });
    };

    info!("🔑 Secret revealed for swap {}: {}", swap.id, secret);

    if let Err(e) = app_state.database.update_swap_secret(&swap.id, secret) {
        error!("Failed to update secret for swap {}: {}", swap.id, e);
        return HttpResponse::InternalServerError().json(IndexerEventResponse {
            success: false,
            message: "Failed to update swap secret".to_string(),
            error: Some(e.to_string()),
        });
    }

    // Store redemption event
    let event = HTLCEvent {
        event_id: format!("redemption_{}", swap.id),
        swap_id: swap.id.clone(),
        event_type: HTLCEventType::Redeemed {
            secret: secret.clone(),
        },
        chain: request.chain.clone(),
        block_number: 0,
        transaction_hash: request.transaction_hash.clone(),
        timestamp: chrono::Utc::now(),
    };

    if let Err(e) = app_state.database.store_event(&event) {
        error!("Failed to store redemption event: {}", e);
    }

    info!(
        "✅ Secret stored for swap {}, coordinator will complete redemption",
        swap.id
    );

    HttpResponse::Ok().json(IndexerEventResponse {
        success: true,
        message: "Secret updated, coordinator will complete swap".to_string(),
        error: None,
    })
}

pub async fn handle_htlc_created_event(
    app_state: &web::Data<AppState>,
    request: &IndexerEventRequest,
) -> HttpResponse {
    info!(
        "🔗 HTLC created on {} | TxHash: {}",
        request.chain, request.transaction_hash
    );

    let hash_lock = match &request.hash_lock {
        Some(h) => h,
        None => {
            return HttpResponse::BadRequest().json(IndexerEventResponse {
                success: false,
                message: "HTLC created event missing hash_lock".to_string(),
                error: None,
            });
        }
    };

    // Parse pool_type from event (emitted by contract as felt252: 0 or 1)
    let pool_type = match request.pool_type.as_str() {
        "0" | "fast" | "Fast" => PoolType::Fast,
        "1" | "standard" | "Standard" => PoolType::Standard,
        _ => {
            return HttpResponse::BadRequest().json(IndexerEventResponse {
                success: false,
                message: format!("Invalid pool_type: {}", request.pool_type),
                error: None,
            });
        }
    };

    info!(
        "🔒 HTLC Created | Pool: {:?} | HashLock: {}",
        pool_type,
        &hash_lock[..8],
    );

    let swap = match app_state.database.get_swap_by_hash_lock(hash_lock) {
        Ok(Some(swap)) => swap,
        Ok(None) => {
            return HttpResponse::NotFound().json(IndexerEventResponse {
                success: false,
                message: "Swap not found for hash_lock".to_string(),
                error: Some(format!("No swap found for hash_lock: {}", hash_lock)),
            });
        }
        Err(e) => {
            error!("Database error: {}", e);
            return HttpResponse::InternalServerError().json(IndexerEventResponse {
                success: false,
                message: "Failed to lookup swap".to_string(),
                error: Some(e.to_string()),
            });
        }
    };

    info!("📍 Found swap: {} for HTLC creation", swap.id);

    let result = match request.chain.as_str() {
        "starknet" => {
            let nullifier = match &request.nullifier {
                Some(n) => n,
                None => {
                    return HttpResponse::BadRequest().json(IndexerEventResponse {
                        success: false,
                        message: "Starknet HTLC created event missing nullifier".to_string(),
                        error: None,
                    });
                }
            };

            app_state
                .database
                .update_starknet_htlc_nullifier(&swap.id, nullifier)
        }
        "zcash" => app_state
            .database
            .update_zcash_txid(&swap.id, &request.transaction_hash),
        _ => {
            return HttpResponse::BadRequest().json(IndexerEventResponse {
                success: false,
                message: format!("Unknown chain: {}", request.chain),
                error: None,
            });
        }
    };

    match result {
        Ok(_) => {
            // Store HTLC initiated event
            let event = HTLCEvent {
                event_id: format!("htlc_created_{}", swap.id),
                swap_id: swap.id.clone(),
                event_type: HTLCEventType::Initiated {
                    hash_lock: hash_lock.clone(),
                    nullifier: request.nullifier.clone(),
                    pool_type: format!("{:?}", pool_type),
                    initiator: request.stealth_initiator.clone().unwrap_or_default(),
                    participant: request.stealth_participant.clone().unwrap_or_default(),
                },
                chain: request.chain.clone(),
                block_number: 0,
                transaction_hash: request.transaction_hash.clone(),
                timestamp: chrono::Utc::now(),
            };

            if let Err(e) = app_state.database.store_event(&event) {
                error!("Failed to store HTLC created event: {}", e);
            }

            info!("✅ {} HTLC registered for swap {}", request.chain, swap.id);
            HttpResponse::Ok().json(IndexerEventResponse {
                success: true,
                message: format!("{} HTLC registered for swap {}", request.chain, swap.id),
                error: None,
            })
        }
        Err(e) => {
            error!("Failed to update HTLC for swap {}: {}", swap.id, e);
            HttpResponse::InternalServerError().json(IndexerEventResponse {
                success: false,
                message: "Failed to update HTLC info".to_string(),
                error: Some(e.to_string()),
            })
        }
    }
}

pub async fn handle_refund_event(
    app_state: &web::Data<AppState>,
    request: &IndexerEventRequest,
) -> HttpResponse {
    info!("♻️ Refund event received on chain: {}", request.chain);

    // Parse pool_type from event (emitted by contract as felt252: 0 or 1)
    let pool_type = match request.pool_type.as_str() {
        "0" | "fast" | "Fast" => PoolType::Fast,
        "1" | "standard" | "Standard" => PoolType::Standard,
        _ => {
            return HttpResponse::BadRequest().json(IndexerEventResponse {
                success: false,
                message: format!("Invalid pool_type: {}", request.pool_type),
                error: None,
            });
        }
    };

    let hash_lock = request.hash_lock.as_ref();

    if let Some(hl) = hash_lock {
        info!("🔒 Refund | Pool: {:?} | HashLock: {}", pool_type, &hl[..8],);
    } else {
        info!("🔒 Refund | Pool: {:?}", pool_type);
    }

    let swap = if let Some(nullifier) = &request.nullifier {
        match app_state.database.get_swap_by_nullifier(nullifier) {
            Ok(Some(swap)) => swap,
            Ok(None) => {
                return HttpResponse::NotFound().json(IndexerEventResponse {
                    success: false,
                    message: "Swap not found for nullifier".to_string(),
                    error: Some(format!("No swap found for nullifier: {}", nullifier)),
                });
            }
            Err(e) => {
                error!("Database error looking up swap by nullifier: {}", e);
                return HttpResponse::InternalServerError().json(IndexerEventResponse {
                    success: false,
                    message: "Failed to lookup swap".to_string(),
                    error: Some(e.to_string()),
                });
            }
        }
    } else if let Some(commitment) = &request.commitment {
        match app_state.database.get_swap_by_commitment(commitment) {
            Ok(Some(swap)) => swap,
            Ok(None) => {
                return HttpResponse::NotFound().json(IndexerEventResponse {
                    success: false,
                    message: "Swap not found for commitment".to_string(),
                    error: Some(format!("No swap found for commitment: {}", commitment)),
                });
            }
            Err(e) => {
                error!("Database error looking up swap by commitment: {}", e);
                return HttpResponse::InternalServerError().json(IndexerEventResponse {
                    success: false,
                    message: "Failed to lookup swap".to_string(),
                    error: Some(e.to_string()),
                });
            }
        }
    } else if let Some(hash_lock) = &request.hash_lock {
        match app_state.database.get_swap_by_hash_lock(hash_lock) {
            Ok(Some(swap)) => swap,
            Ok(None) => {
                return HttpResponse::NotFound().json(IndexerEventResponse {
                    success: false,
                    message: "Swap not found for hash_lock".to_string(),
                    error: Some(format!("No swap found for hash_lock: {}", hash_lock)),
                });
            }
            Err(e) => {
                error!("Database error looking up swap by hash_lock: {}", e);
                return HttpResponse::InternalServerError().json(IndexerEventResponse {
                    success: false,
                    message: "Failed to lookup swap".to_string(),
                    error: Some(e.to_string()),
                });
            }
        }
    } else {
        return HttpResponse::BadRequest().json(IndexerEventResponse {
            success: false,
            message: "Must provide nullifier, commitment, or hash_lock".to_string(),
            error: None,
        });
    };

    info!("♻️ Processing refund for swap {}", swap.id);

    if let Err(e) = app_state
        .database
        .update_swap_status(&swap.id, SwapStatus::Refunded)
    {
        error!("Failed to update refund status for swap {}: {}", swap.id, e);
        return HttpResponse::InternalServerError().json(IndexerEventResponse {
            success: false,
            message: "Failed to update swap status".to_string(),
            error: Some(e.to_string()),
        });
    }

    // Store refund event
    let event = HTLCEvent {
        event_id: format!("refund_{}", swap.id),
        swap_id: swap.id.clone(),
        event_type: HTLCEventType::Refunded {
            pool_type: format!("{:?}", pool_type),
        },
        chain: request.chain.clone(),
        block_number: 0,
        transaction_hash: request.transaction_hash.clone(),
        timestamp: chrono::Utc::now(),
    };

    if let Err(e) = app_state.database.store_event(&event) {
        error!("Failed to store refund event: {}", e);
    }

    info!("✅ Swap {} marked as refunded", swap.id);

    HttpResponse::Ok().json(IndexerEventResponse {
        success: true,
        message: "Swap marked as refunded".to_string(),
        error: None,
    })
}

pub fn validate_hmac(
    req: &HttpRequest,
    body: &web::Bytes,
    app_state: &web::Data<AppState>,
) -> Result<(), HttpResponse> {
    let timestamp = match req.headers().get("x-timestamp") {
        Some(ts) => match ts.to_str() {
            Ok(s) => s,
            Err(_) => {
                return Err(HttpResponse::BadRequest().json(json!({
                    "success": false,
                    "message": "Invalid timestamp header"
                })));
            }
        },
        None => {
            return Err(HttpResponse::BadRequest().json(json!({
                "success": false,
                "message": "Missing x-timestamp header"
            })));
        }
    };

    let provided_signature = match req.headers().get("x-signature") {
        Some(sig) => match sig.to_str() {
            Ok(s) => s,
            Err(_) => {
                return Err(HttpResponse::BadRequest().json(json!({
                    "success": false,
                    "message": "Invalid signature header"
                })));
            }
        },
        None => {
            return Err(HttpResponse::BadRequest().json(json!({
                "success": false,
                "message": "Missing x-signature header"
            })));
        }
    };

    let hmac_secret = &app_state.config.server.hmac_secret;

    let body_str = match std::str::from_utf8(body) {
        Ok(s) => s,
        Err(_) => {
            return Err(HttpResponse::BadRequest().json(json!({
                "success": false,
                "message": "Invalid UTF-8 in body"
            })));
        }
    };

    let message = format!("{}{}", timestamp, body_str);

    info!("HMAC Debug - Timestamp: {}", timestamp);
    info!("HMAC Debug - Body length: {}", body_str.len());
    info!("HMAC Debug - Message: {}", message);

    let mut mac =
        HmacSha256::new_from_slice(hmac_secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(message.as_bytes());
    let expected_signature = hex::encode(mac.finalize().into_bytes());

    if provided_signature != expected_signature {
        error!(
            "Invalid HMAC signature. Expected: {}, Got: {}",
            expected_signature, provided_signature
        );
        return Err(HttpResponse::Unauthorized().json(json!({
            "success": false,
            "message": "Invalid signature"
        })));
    }

    Ok(())
}
