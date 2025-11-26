use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder};
use chrono::Utc;
use serde_json::json;
use tracing::{error, info};

use crate::{
    api::helpers::{
        determine_pool_type, handle_htlc_created_event, handle_redemption_event,
        handle_refund_event, validate_hmac,
    },
    database::model::SwapPrivacyParams,
    merkle_tree::model::PoolType,
    models::models::{
        IndexerEventRequest, IndexerEventResponse, InitiateSwapRequest, InitiateSwapResponse,
        SwapPair, SwapStatus,
    },
    AppState,
};

#[post("/swap/initiate")]
pub async fn initiate_swap(
    req: HttpRequest,
    app_state: web::Data<AppState>,
    body: web::Bytes,
) -> impl Responder {
    if let Err(response) = validate_hmac(&req, &body, &app_state) {
        return response;
    }

    let request: InitiateSwapRequest = match serde_json::from_slice(&body) {
        Ok(req) => req,
        Err(e) => {
            return HttpResponse::BadRequest().json(InitiateSwapResponse {
                success: false,
                swap_id: String::new(),
                message: "Invalid request format".to_string(),
                error: Some(e.to_string()),
            });
        }
    };

    let swap_id = format!(
        "swap_{}_{}_{}",
        request.swap_direction,
        request.user_address.chars().take(8).collect::<String>(),
        Utc::now().timestamp()
    );

    info!(
        "📥 Initiating swap: {} | Direction: {} | Amount: {} STRK / {} ZEC",
        swap_id, request.swap_direction, request.starknet_amount, request.zcash_amount
    );

    if request.swap_direction != "starknet_to_zcash"
        && request.swap_direction != "zcash_to_starknet"
    {
        return HttpResponse::BadRequest().json(InitiateSwapResponse {
            success: false,
            swap_id: swap_id.clone(),
            message: "Invalid swap direction".to_string(),
            error: Some("Must be 'starknet_to_zcash' or 'zcash_to_starknet'".to_string()),
        });
    }

    let pool_type = match determine_pool_type(&request.starknet_amount) {
        Ok(pt) => pt,
        Err(e) => {
            return HttpResponse::BadRequest().json(InitiateSwapResponse {
                success: false,
                swap_id: swap_id.clone(),
                message: "Invalid amount".to_string(),
                error: Some(e),
            });
        }
    };

    let pool_name = match pool_type {
        PoolType::Fast => "Fast",
        PoolType::Standard => "Standard",
    };

    info!(
        "📊 Routing to {} Pool (<$10K = Fast, ≥$10K = Standard)",
        pool_name
    );

    if request.swap_direction == "starknet_to_zcash" {
        let token_address = app_state.config.starknet.token_address.clone();

        let tree_size = app_state
            .merkle_tree_manager
            .get_set_size(&token_address, pool_type)
            .await;

        if tree_size == 0 {
            return HttpResponse::BadRequest().json(InitiateSwapResponse {
                success: false,
                swap_id: swap_id.clone(),
                message: "No deposits found in pool - user must deposit first".to_string(),
                error: Some("Call pool.deposit() before initiating swap".to_string()),
            });
        }

        // Verify commitment can generate a valid proof (exists in tree)
        match app_state
            .merkle_tree_manager
            .generate_proof(&token_address, &request.commitment, pool_type)
            .await
        {
            Ok(proof) => match app_state.starknet_relayer.get_current_root(pool_type).await {
                Ok(on_chain_root) => {
                    if proof.root != on_chain_root {
                        return HttpResponse::BadRequest().json(InitiateSwapResponse {
                            success: false,
                            swap_id: swap_id.clone(),
                            message: "Merkle tree not synced - please wait for next root update"
                                .to_string(),
                            error: Some(format!(
                                "Local root: {}, On-chain root: {}",
                                proof.root, on_chain_root
                            )),
                        });
                    }
                }
                Err(e) => {
                    error!("Failed to get on-chain root: {}", e);
                    return HttpResponse::InternalServerError().json(InitiateSwapResponse {
                        success: false,
                        swap_id: swap_id.clone(),
                        message: "Failed to verify on-chain state".to_string(),
                        error: Some(e.to_string()),
                    });
                }
            },
            Err(e) => {
                return HttpResponse::BadRequest().json(InitiateSwapResponse {
                    success: false,
                    swap_id: swap_id.clone(),
                    message: "Commitment not found in pool - user must deposit first".to_string(),
                    error: Some(format!("No valid merkle proof for commitment: {}", e)),
                });
            }
        }

        info!("✅ Commitment verified in merkle tree for swap {}", swap_id);
    }

    let now = Utc::now().timestamp() as u64;
    let starknet_timelock = now + 86400;
    let zcash_timelock = now + 172800;

    let privacy_params_result = app_state.starknet_relayer.generate_privacy_params(
        &request.user_address,
        &request.starknet_amount,
        Utc::now().timestamp(),
    );

    let privacy_params = match privacy_params_result {
        Ok(params) => params,
        Err(e) => {
            error!("Failed to generate privacy params: {}", e);
            return HttpResponse::InternalServerError().json(InitiateSwapResponse {
                success: false,
                swap_id: swap_id.clone(),
                message: "Failed to generate privacy parameters".to_string(),
                error: Some(e.to_string()),
            });
        }
    };

    let swap = SwapPair {
        id: swap_id.clone(),
        starknet_htlc_nullifier: None,
        zcash_txid: None,
        initiator: request.user_address.clone(),
        responder: "relayer_pool".to_string(),
        hash_lock: request.hash_lock.clone(),
        secret: None,
        starknet_amount: request.starknet_amount.clone(),
        zcash_amount: request.zcash_amount.clone(),
        starknet_timelock,
        zcash_timelock,
        status: SwapStatus::Initiated,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    let token_address = app_state.config.starknet.token_address.clone();

    let swap_privacy_params = SwapPrivacyParams {
        swap_id: swap_id.clone(),
        initiator: request.user_address.clone(),
        participant: "relayer_pool".to_string(),
        hash_lock: request.hash_lock.clone(),
        starknet_amount: request.starknet_amount.clone(),
        zcash_amount: request.zcash_amount.clone(),
        starknet_timelock,
        zcash_timelock,
        starknet_htlc_nullifier: None,
        zcash_recipient: Some(app_state.config.zcash.pool_address.clone()),
        stealth_initiator: Some(privacy_params.stealth_initiator.clone()),
        stealth_participant: Some(privacy_params.stealth_participant.clone()),
        token_address: Some(token_address),
        amount_commitment: Some(request.commitment.clone()),
        encrypted_data: Some(privacy_params.encrypted_data.clone()),
        ephemeral_pubkey: Some(privacy_params.ephemeral_pubkey.clone()),
        range_proof: Some(serde_json::to_string(&privacy_params.range_proof).unwrap_or_default()),
        bit_blinding_seed: Some(privacy_params.bit_blinding_seed.clone()),
        blinding_factor: Some(privacy_params.blinding_factor.clone()),
    };

    if let Err(e) = app_state
        .database
        .create_swap_with_privacy(&swap, &swap_privacy_params)
    {
        error!("Failed to create swap {}: {}", swap_id, e);
        return HttpResponse::InternalServerError().json(InitiateSwapResponse {
            success: false,
            swap_id: swap_id.clone(),
            message: "Failed to initialize swap".to_string(),
            error: Some(e.to_string()),
        });
    }

    info!("✅ Swap {} initiated successfully", swap_id);

    HttpResponse::Ok().json(InitiateSwapResponse {
        success: true,
        swap_id,
        message: "Swap initiated successfully. Relayer will process the counter-HTLC.".to_string(),
        error: None,
    })
}

#[post("/indexer/event")]
pub async fn indexer_event(
    req: HttpRequest,
    app_state: web::Data<AppState>,
    body: web::Bytes,
) -> impl Responder {
    if let Err(response) = validate_hmac(&req, &body, &app_state) {
        return response;
    }

    let request: IndexerEventRequest = match serde_json::from_slice(&body) {
        Ok(req) => req,
        Err(e) => {
            return HttpResponse::BadRequest().json(IndexerEventResponse {
                success: false,
                message: "Invalid request format".to_string(),
                error: Some(e.to_string()),
            });
        }
    };

    info!(
        "📡 Indexer event: {} | Chain: {} | TxHash: {}",
        request.event_type, request.chain, request.transaction_hash
    );

    match request.event_type.as_str() {
        "htlc_redeemed" => handle_redemption_event(&app_state, &request).await,
        "htlc_created" => handle_htlc_created_event(&app_state, &request).await,
        "htlc_refunded" => handle_refund_event(&app_state, &request).await,
        _ => HttpResponse::BadRequest().json(IndexerEventResponse {
            success: false,
            message: format!("Unknown event type: {}", request.event_type),
            error: None,
        }),
    }
}

#[get("/")]
pub async fn root() -> impl Responder {
    HttpResponse::Ok().json(json!({
        "service": "Shadow Swap Relayer",
        "version": "1.0.0",
        "status": "operational"
    }))
}

#[get("/health")]
pub async fn health_check() -> impl Responder {
    HttpResponse::Ok().json(json!({
        "status": "healthy",
        "timestamp": Utc::now().to_rfc3339()
    }))
}

#[get("/metrics")]
pub async fn get_metrics(app_state: web::Data<AppState>) -> impl Responder {
    let metrics = app_state.coordinator.get_metrics().await;

    HttpResponse::Ok().json(json!({
        "status": "success",
        "data": metrics.to_json()
    }))
}

#[get("/stats")]
pub async fn get_stats(app_state: web::Data<AppState>) -> impl Responder {
    match app_state.database.get_coordinator_stats() {
        Ok(stats) => HttpResponse::Ok().json(json!({
            "status": "success",
            "data": {
                "total_swaps": stats.total_swaps,
                "successful_swaps": stats.successful_swaps,
                "failed_swaps": stats.failed_swaps,
                "refunded_swaps": stats.refunded_swaps,
                "pending_swaps": stats.pending_swaps,
                "critical_swaps": stats.critical_swaps
            }
        })),
        Err(e) => {
            error!("Failed to get stats: {}", e);
            HttpResponse::InternalServerError().json(json!({
                "status": "error",
                "message": "Failed to retrieve statistics"
            }))
        }
    }
}

#[get("/swap/{swap_id}")]
pub async fn get_swap_status(
    app_state: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let swap_id = path.into_inner();

    match app_state.database.get_swap_by_id(&swap_id) {
        Ok(Some(swap)) => HttpResponse::Ok().json(json!({
            "status": "success",
            "data": {
                "swap_id": swap.id,
                "status": swap.status.as_str(),
                "starknet_amount": swap.starknet_amount,
                "zcash_amount": swap.zcash_amount,
                "starknet_htlc_nullifier": swap.starknet_htlc_nullifier,
                "zcash_txid": swap.zcash_txid,
                "created_at": swap.created_at,
                "updated_at": swap.updated_at
            }
        })),
        Ok(None) => HttpResponse::NotFound().json(json!({
            "status": "error",
            "message": "Swap not found"
        })),
        Err(e) => {
            error!("Failed to get swap {}: {}", swap_id, e);
            HttpResponse::InternalServerError().json(json!({
                "status": "error",
                "message": "Failed to retrieve swap"
            }))
        }
    }
}
