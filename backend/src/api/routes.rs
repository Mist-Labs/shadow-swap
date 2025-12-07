use actix_web::{get, post, web, HttpRequest, HttpResponse, Responder};
use chrono::Utc;
use serde_json::json;
use tracing::{error, info};

use crate::{
    api::helpers::{
        handle_deposit_event, handle_htlc_created_event, handle_redemption_event,
        handle_refund_event, validate_hmac,
    },
    database::model::SwapPrivacyParams,
    merkle_tree::model::PoolType,
    models::models::{
        AllPricesResponse, ConvertRequest, ConvertResponse, IndexerEventRequest,
        IndexerEventResponse, InitiateSwapRequest, InitiateSwapResponse, PriceRequest,
        PriceResponse, PriceSourceInfo, SwapPair, SwapStatus,
    },
    pricefeed::pricefeed::get_current_rate,
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

    info!("🔄 Initiating swap for commitment: {}", request.commitment);

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

    // ✅ Only determine pool_type for routing display purposes
    let token = if request.swap_direction == "starknet_to_zcash" {
        "STRK"
    } else {
        "ZEC"
    };

    let amount = if request.swap_direction == "starknet_to_zcash" {
        &request.starknet_amount
    } else {
        &request.zcash_amount
    };

    info!("📊 Routing to Pool (<$10K = Fast, ≥$10K = Standard)");

    if request.swap_direction == "starknet_to_zcash" {
        let token_address = app_state.config.starknet.token_address.clone();
        info!("Token address: {}", token_address);

        // ✅ Get deposit status WITHOUT filtering by pool_type
        let deposit_status = match app_state.database.get_deposit_status(&request.commitment) {
            Ok(status) => status,
            Err(e) => {
                error!("Failed to check deposit status: {}", e);
                return HttpResponse::InternalServerError().json(InitiateSwapResponse {
                    success: false,
                    swap_id: swap_id.clone(),
                    message: "Failed to verify deposit".to_string(),
                    error: Some(e.to_string()),
                });
            }
        };

        match deposit_status {
            None => {
                return HttpResponse::BadRequest().json(InitiateSwapResponse {
                    success: false,
                    swap_id: swap_id.clone(),
                    message: "No deposit found - please deposit first".to_string(),
                    error: Some("Commitment not found in database".to_string()),
                });
            }
            Some(status) if !status.in_merkle_tree => {
                let actual_pool_type = match status.pool_type.as_str() {
                    "fast" => PoolType::Fast,
                    "standard" => PoolType::Standard,
                    _ => PoolType::Fast,
                };

                let wait_time = match actual_pool_type {
                    PoolType::Fast => "30 seconds",
                    PoolType::Standard => "2 minutes",
                };

                return HttpResponse::BadRequest().json(InitiateSwapResponse {
                    success: false,
                    swap_id: swap_id.clone(),
                    message: format!(
                        "Deposit found but Merkle tree is updating. Please wait up to {} and try again.",
                        wait_time
                    ),
                    error: Some("Commitment pending Merkle tree inclusion".to_string()),
                });
            }
            Some(status) => {
                let pool_type = match status.pool_type.as_str() {
                    "fast" => PoolType::Fast,
                    "standard" => PoolType::Standard,
                    _ => {
                        error!("❌ Invalid pool_type in database: {}", status.pool_type);
                        return HttpResponse::InternalServerError().json(InitiateSwapResponse {
                            success: false,
                            swap_id: swap_id.clone(),
                            message: "Internal error - invalid pool type".to_string(),
                            error: Some(format!("Invalid pool_type: {}", status.pool_type)),
                        });
                    }
                };

                info!("✅ Using {:?} pool from database record", pool_type);
                info!(
                    "✅ Deposit found in Merkle tree at index: {:?}",
                    status.merkle_index
                );

                match app_state
                    .merkle_tree_manager
                    .generate_proof(&token_address, &request.commitment, pool_type)
                    .await
                {
                    Ok(proof) => {
                        match app_state.starknet_relayer.get_current_root(pool_type).await {
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
                                return HttpResponse::InternalServerError().json(
                                    InitiateSwapResponse {
                                        success: false,
                                        swap_id: swap_id.clone(),
                                        message: "Failed to verify on-chain state".to_string(),
                                        error: Some(e.to_string()),
                                    },
                                );
                            }
                        }
                    }
                    Err(e) => {
                        error!("❌ Failed to generate proof: {}", e);
                        return HttpResponse::InternalServerError().json(InitiateSwapResponse {
                            success: false,
                            swap_id: swap_id.clone(),
                            message: "Internal error - please contact support".to_string(),
                            error: Some(format!("Merkle proof generation failed: {}", e)),
                        });
                    }
                }
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
        "deposit" => handle_deposit_event(&app_state, &request).await,
        "htlc_created" => handle_htlc_created_event(&app_state, &request).await,
        "htlc_redeemed" => handle_redemption_event(&app_state, &request).await,
        "htlc_refunded" => handle_refund_event(&app_state, &request).await,
        _ => HttpResponse::BadRequest().json(IndexerEventResponse {
            success: false,
            message: format!("Unknown event type: {}", request.event_type),
            error: None,
        }),
    }
}

#[get("/price")]
pub async fn get_price(
    query: web::Query<PriceRequest>,
    data: web::Data<AppState>,
) -> impl Responder {
    let pair_key = format!(
        "{}-{}",
        query.from_symbol.to_uppercase(),
        query.to_symbol.to_uppercase()
    );

    info!("📊 Price query for: {}", pair_key);

    match data.price_cache.get_price_data(&pair_key) {
        Some(price_data) => {
            let data_guard = match price_data.lock() {
                Ok(guard) => guard,
                Err(e) => {
                    error!("Failed to acquire price data lock: {}", e);
                    return HttpResponse::InternalServerError().json(json!({
                        "error": "Failed to acquire price data lock"
                    }));
                }
            };

            if data_guard.price <= 0.0 {
                return HttpResponse::ServiceUnavailable().json(json!({
                    "error": "Price data not yet available",
                    "pair": pair_key
                }));
            }

            let converted_amount = query.amount.map(|amt| amt * data_guard.price);

            let response = PriceResponse {
                from_symbol: query.from_symbol.to_uppercase(),
                to_symbol: query.to_symbol.to_uppercase(),
                rate: data_guard.price,
                amount: query.amount,
                converted_amount,
                timestamp: data_guard.timestamp,
                sources: data_guard
                    .sources
                    .iter()
                    .map(|s| PriceSourceInfo {
                        source: s.source.clone(),
                        price: s.price,
                    })
                    .collect(),
            };

            HttpResponse::Ok().json(response)
        }
        None => HttpResponse::NotFound().json(json!({
            "error": "Price feed not found",
            "pair": pair_key,
            "available_pairs": ["STRK-ZEC", "ZEC-STRK", "STRK-USD", "ZEC-USD"]
        })),
    }
}

#[get("/prices/all")]
pub async fn get_all_prices(data: web::Data<AppState>) -> impl Responder {
    info!("📊 Fetching all prices");

    let mut response = AllPricesResponse {
        strk_to_zec: 0.0,
        zec_to_strk: 0.0,
        strk_to_usd: 0.0,
        zec_to_usd: 0.0,
        timestamp: chrono::Utc::now().timestamp(),
    };

    if let Some(price_data) = data.price_cache.get_price_data("STRK-ZEC") {
        if let Ok(data_guard) = price_data.lock() {
            response.strk_to_zec = data_guard.price;
        }
    }

    if let Some(price_data) = data.price_cache.get_price_data("ZEC-STRK") {
        if let Ok(data_guard) = price_data.lock() {
            response.zec_to_strk = data_guard.price;
        }
    }

    if let Some(price_data) = data.price_cache.get_price_data("STRK-USD") {
        if let Ok(data_guard) = price_data.lock() {
            response.strk_to_usd = data_guard.price;
        }
    }

    if let Some(price_data) = data.price_cache.get_price_data("ZEC-USD") {
        if let Ok(data_guard) = price_data.lock() {
            response.zec_to_usd = data_guard.price;
        }
    }

    HttpResponse::Ok().json(response)
}

#[post("/price/convert")]
pub async fn convert_amount(
    req: web::Json<ConvertRequest>,
    data: web::Data<AppState>,
) -> impl Responder {
    let pair_key = format!(
        "{}-{}",
        req.from_symbol.to_uppercase(),
        req.to_symbol.to_uppercase()
    );

    info!(
        "💱 Convert request: {} {} to {}",
        req.amount, req.from_symbol, req.to_symbol
    );

    match data.price_cache.get_price_data(&pair_key) {
        Some(price_data) => match get_current_rate(price_data) {
            Ok(rate) => {
                let output_amount = req.amount * rate;

                let response = ConvertResponse {
                    from_symbol: req.from_symbol.to_uppercase(),
                    to_symbol: req.to_symbol.to_uppercase(),
                    input_amount: req.amount,
                    output_amount,
                    rate,
                    timestamp: chrono::Utc::now().timestamp(),
                };

                HttpResponse::Ok().json(response)
            }
            Err(e) => {
                error!("Failed to get current rate: {}", e);
                HttpResponse::ServiceUnavailable().json(json!({
                    "error": format!("Failed to get exchange rate: {}", e)
                }))
            }
        },
        None => HttpResponse::NotFound().json(json!({
            "error": "Price feed not found",
            "pair": pair_key
        })),
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
