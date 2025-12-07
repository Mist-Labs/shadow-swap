mod api;
mod config;
mod crypto;
mod database;
mod merkle_tree;
mod models;
mod pricefeed;
mod relay_coordinator;
mod starknet;
mod zcash;

use std::sync::Arc;

use actix_cors::Cors;
use actix_web::{http::header, middleware::Logger, web, App, HttpServer};
use dotenv::dotenv;
use tokio::task;
use tracing::{error, info};

use crate::{
    config::{config_scope, model::RelayerConfig},
    database::database::Database,
    merkle_tree::model::MerkleTreeManager,
    pricefeed::pricefeed::PriceCache,
    relay_coordinator::{
        model::{RelayCoordinator, RetryConfig},
        secret_monitor::SecretMonitor,
    },
    starknet::relayer::StarknetRelayer,
    zcash::model::ZcashRelayer,
};

pub struct AppState {
    pub database: Arc<Database>,
    pub config: RelayerConfig,
    pub merkle_tree_manager: Arc<MerkleTreeManager>,
    pub starknet_relayer: Arc<StarknetRelayer>,
    pub zcash_relayer: Arc<ZcashRelayer>,
    pub coordinator: Arc<RelayCoordinator>,
    pub secret_monitor: Arc<SecretMonitor>,
    pub price_cache: Arc<PriceCache>,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    // Initialize logging - FIX: Use simpler initialization
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "shadow_swap=info,actix_web=info,diesel=warn".into()),
        )
        .init();

    info!("🚀 Starting Shadow Swap Relayer");

    let config = RelayerConfig::from_env()
        .or_else(|_| RelayerConfig::from_file("config.toml".into()))
        .expect("Failed to load configuration");

    let database = Arc::new(
        Database::new(&config.database.url, config.database.max_connections)
            .expect("Failed to initialize database"),
    );

    info!("📊 Running database migrations");
    database.run_migrations().expect("Failed to run migrations");

    info!("💱 Initializing price feeds");
    let price_cache = Arc::new(PriceCache::new());

    // Initialize STRK -> ZEC price feed
    info!("📈 Starting STRK->ZEC price feed");
    let strk_zec_feed = pricefeed::pricefeed::init_price_feed("STRK", "ZEC").await;
    price_cache.insert_price_data("STRK-ZEC".to_string(), strk_zec_feed);

    // Initialize ZEC -> STRK price feed
    info!("📈 Starting ZEC->STRK price feed");
    let zec_strk_feed = pricefeed::pricefeed::init_price_feed("ZEC", "STRK").await;
    price_cache.insert_price_data("ZEC-STRK".to_string(), zec_strk_feed);

    // Initialize USD price feeds for reference
    info!("📈 Starting STRK->USD price feed");
    let strk_usd_feed = pricefeed::pricefeed::init_price_feed("STRK", "USD").await;
    price_cache.insert_price_data("STRK-USD".to_string(), strk_usd_feed);

    info!("📈 Starting ZEC->USD price feed");
    let zec_usd_feed = pricefeed::pricefeed::init_price_feed("ZEC", "USD").await;
    price_cache.insert_price_data("ZEC-USD".to_string(), zec_usd_feed);

    info!("🔗 Initializing Starknet relayer");
    let starknet_relayer = Arc::new(
        StarknetRelayer::new(config.starknet.clone(), database.clone())
            .await
            .expect("Failed to initialize Starknet relayer"),
    );

    info!("🔒 Initializing Zcash relayer");
    let zcash_relayer = Arc::new(ZcashRelayer::new(config.zcash.clone(), database.clone()));
    zcash_relayer
        .initialize()
        .await
        .expect("Failed to import Zcash relayer private key");

    info!("🌳 Initializing Merkle Tree Manager");
    let tree_depth = 20;
    let merkle_tree_manager = Arc::new(MerkleTreeManager::new(
        starknet_relayer.clone(),
        starknet_relayer.clone(),
        database.clone(),
        tree_depth,
    ));

    info!("🔍 Initializing secret monitor");
    let secret_monitor = Arc::new(SecretMonitor::new(
        starknet_relayer.clone(),
        zcash_relayer.clone(),
        database.clone(),
    ));

    info!("🎯 Initializing relay coordinator");
    let coordinator = Arc::new(
        RelayCoordinator::new(
            starknet_relayer.clone(),
            zcash_relayer.clone(),
            database.clone(),
            merkle_tree_manager.clone(),
            price_cache.clone(),
        )
        .retry_with_config(RetryConfig {
            max_attempts: 5,
            initial_delay_ms: 1000,
            max_delay_ms: 60000,
            backoff_multiplier: 2.0,
        }),
    );

    let app_state = web::Data::new(AppState {
        database,
        config: config.clone(),
        merkle_tree_manager: merkle_tree_manager.clone(),
        starknet_relayer,
        zcash_relayer,
        coordinator: coordinator.clone(),
        secret_monitor: secret_monitor.clone(),
        price_cache,
    });

    info!("🌳 Starting Merkle Tree Manager service");
    let tree_manager_handle = task::spawn({
        let manager = merkle_tree_manager.clone();
        async move {
            if let Err(e) = manager.start().await {
                error!("❌ Merkle Tree Manager error: {}", e);
            }
        }
    });

    info!("🔍 Starting secret monitor service");
    let monitor_handle = task::spawn({
        let monitor = secret_monitor.clone();
        async move {
            if let Err(e) = monitor.start().await {
                error!("❌ Secret monitor error: {}", e);
            }
        }
    });

    info!("⚙️  Starting coordinator service");
    let coordinator_clone = coordinator.clone();
    std::thread::spawn(move || {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            if let Err(e) = coordinator_clone.start().await {
                error!("❌ Coordinator error: {}", e);
            }
        });
    });

    let host = config.server.host.clone();
    let port = config.server.port;

    info!("🌐 Starting HTTP server on {}:{}", host, port);

    let server = HttpServer::new(move || {
        let cors = Cors::default()
            .allowed_origin("http://localhost:3000")
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
            .allowed_headers(vec![
                header::CONTENT_TYPE,
                header::AUTHORIZATION,
                header::ACCEPT,
            ])
            .supports_credentials()
            .max_age(3600);

        App::new()
            .app_data(app_state.clone())
            .configure(config_scope::configure)
            .wrap(cors)
            .wrap(Logger::default())
    })
    .bind((host.as_str(), port))?
    .run();

    info!("✅ All services started successfully");

    tokio::select! {
        result = server => error!("HTTP server stopped: {:?}", result),
        _ = monitor_handle => error!("Secret monitor stopped unexpectedly"),
        _ = tree_manager_handle => error!("Merkle Tree Manager stopped unexpectedly"),
    }

    Ok(())
}

// RUST_LOG="debug" cargo run