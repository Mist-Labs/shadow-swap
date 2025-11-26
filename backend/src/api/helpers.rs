use actix_web::{HttpRequest, HttpResponse, web};
use hmac::{Hmac, Mac};
use serde_json::json;
use sha2::Sha256;
use tracing::{error, info};

use crate::{
    merkle_tree::model::PoolType,
    AppState, 
    models::models::{IndexerEventRequest, IndexerEventResponse, SwapStatus}
};

type HmacSha256 = Hmac<Sha256>;

pub fn determine_pool_type(amount: &str) -> Result<PoolType, String> {
    let amount_val: f64 = amount
        .parse()
        .map_err(|_| "Invalid amount format".to_string())?;

    if amount_val < 10000.0 {
        Ok(PoolType::Fast)
    } else {
        Ok(PoolType::Standard)
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

    // Try to find swap by commitment first, then hash_lock
    let swap = if let Some(commitment) = &request.commitment {
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
            message: "Must provide commitment or hash_lock".to_string(),
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

    info!("✅ Secret stored for swap {}, coordinator will complete redemption", swap.id);

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
    info!("🔗 HTLC created on {} | TxHash: {}", request.chain, request.transaction_hash);

    let commitment = match &request.commitment {
        Some(c) => c,
        None => {
            return HttpResponse::BadRequest().json(IndexerEventResponse {
                success: false,
                message: "HTLC created event missing commitment".to_string(),
                error: None,
            });
        }
    };

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

    let swap = match app_state.database.get_swap_by_commitment(commitment) {
        Ok(Some(swap)) => swap,
        Ok(None) => {
            // Try by hash_lock as fallback
            match app_state.database.get_swap_by_hash_lock(hash_lock) {
                Ok(Some(swap)) => swap,
                Ok(None) => {
                    return HttpResponse::NotFound().json(IndexerEventResponse {
                        success: false,
                        message: "Swap not found for commitment or hash_lock".to_string(),
                        error: Some(format!(
                            "No swap found for commitment: {} or hash_lock: {}",
                            commitment, hash_lock
                        )),
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
            }
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
        "zcash" => {
            app_state
                .database
                .update_zcash_txid(&swap.id, &request.transaction_hash)
        }
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
    let body_str = String::from_utf8_lossy(body);
    let message = format!("{}{}", timestamp, body_str);

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