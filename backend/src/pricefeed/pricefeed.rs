use anyhow::{anyhow, Result};
use chrono::Utc;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::time::{self, Duration};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PriceData {
    pub price: f64,
    pub timestamp: i64,
    pub sources: Vec<SourcePrice>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SourcePrice {
    pub source: String,
    pub price: f64,
}

impl Default for PriceData {
    fn default() -> Self {
        PriceData {
            price: 0.0,
            timestamp: Utc::now().timestamp(),
            sources: Vec::new(),
        }
    }
}

// --- CORE FETCHING LOGIC ---

async fn get_cryptocompare_price(from_symbol: &str, to_symbol: &str) -> Result<f64> {
    let client = Client::new();
    let url = format!(
        "https://min-api.cryptocompare.com/data/price?fsym={}&tsyms={}",
        from_symbol, to_symbol
    );
    log::info!("Fetching price from: {}", url);

    let response = client.get(&url).send().await?;

    if response.status().is_success() {
        let data: serde_json::Value = response.json().await?;
        let price = data[to_symbol].as_f64().ok_or_else(|| {
            anyhow!(
                "Cryptocompare: Invalid price format for {}-{}",
                from_symbol,
                to_symbol
            )
        })?;
        Ok(price)
    } else {
        Err(anyhow!(
            "Cryptocompare API error for {}-{}: {}",
            from_symbol,
            to_symbol,
            response.status()
        ))
    }
}

// Alternative: CoinGecko API
async fn get_coingecko_price(from_symbol: &str, to_symbol: &str) -> Result<f64> {
    let client = Client::new();

    // Map symbols to CoinGecko IDs
    let from_id = match from_symbol.to_uppercase().as_str() {
        "STRK" => "starknet",
        "ZEC" => "zcash",
        _ => return Err(anyhow!("Unsupported symbol: {}", from_symbol)),
    };

    let to_currency = to_symbol.to_lowercase();

    let url = format!(
        "https://api.coingecko.com/api/v3/simple/price?ids={}&vs_currencies={}",
        from_id, to_currency
    );

    log::info!("Fetching price from CoinGecko: {}", url);

    let response = client
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .await?;

    if response.status().is_success() {
        let data: serde_json::Value = response.json().await?;
        let price = data[from_id][&to_currency].as_f64().ok_or_else(|| {
            anyhow!(
                "CoinGecko: Invalid price format for {}-{}",
                from_symbol,
                to_symbol
            )
        })?;
        Ok(price)
    } else {
        Err(anyhow!(
            "CoinGecko API error for {}-{}: {}",
            from_symbol,
            to_symbol,
            response.status()
        ))
    }
}

pub async fn get_crypto_usd_rate(from_symbol: &str) -> Result<f64> {
    get_cryptocompare_price(from_symbol, "USD").await
}

pub async fn convert_amount(from_symbol: &str, to_symbol: &str, amount: f64) -> Result<f64> {
    // First try to get direct conversion rate
    match get_cryptocompare_price(from_symbol, to_symbol).await {
        Ok(rate) => {
            log::info!(
                "Direct conversion rate {}->{}: {}",
                from_symbol,
                to_symbol,
                rate
            );
            return Ok(amount * rate);
        }
        Err(e) => {
            log::warn!("Direct conversion failed, trying USD bridge: {}", e);
        }
    }

    // Fallback: Convert through USD
    let from_usd = get_crypto_usd_rate(from_symbol).await?;
    let to_usd = get_crypto_usd_rate(to_symbol).await?;

    let rate = from_usd / to_usd;
    log::info!(
        "Bridge conversion rate {}->{} (via USD): {}",
        from_symbol,
        to_symbol,
        rate
    );

    Ok(amount * rate)
}

// --- CACHING AND COORDINATION LOGIC ---

// Cache for multiple price data
pub struct PriceCache(Mutex<HashMap<String, Arc<Mutex<PriceData>>>>);

impl PriceCache {
    pub fn new() -> Self {
        PriceCache(Mutex::new(HashMap::new()))
    }

    pub fn get_price_data(&self, pair: &str) -> Option<Arc<Mutex<PriceData>>> {
        self.0.lock().unwrap().get(pair).cloned()
    }

    pub fn insert_price_data(&self, pair: String, price_data: Arc<Mutex<PriceData>>) {
        self.0.lock().unwrap().insert(pair, price_data);
    }
}

pub async fn update_price_data_for_pair(
    from_symbol: &str,
    to_symbol: &str,
    price_data: Arc<Mutex<PriceData>>,
) {
    let mut sources = Vec::new();
    let mut sum = 0.0;
    let mut count = 0;

    // Try CryptoCompare
    match get_cryptocompare_price(from_symbol, to_symbol).await {
        Ok(price) => {
            sources.push(SourcePrice {
                source: "CryptoCompare".to_string(),
                price,
            });
            sum += price;
            count += 1;
            log::info!(
                "CryptoCompare price for {}-{}: {}",
                from_symbol,
                to_symbol,
                price
            );
        }
        Err(e) => {
            log::warn!(
                "Error fetching CryptoCompare price for {}-{}: {}",
                from_symbol,
                to_symbol,
                e
            );
        }
    }

    // Try CoinGecko as backup
    match get_coingecko_price(from_symbol, to_symbol).await {
        Ok(price) => {
            sources.push(SourcePrice {
                source: "CoinGecko".to_string(),
                price,
            });
            sum += price;
            count += 1;
            log::info!(
                "CoinGecko price for {}-{}: {}",
                from_symbol,
                to_symbol,
                price
            );
        }
        Err(e) => {
            log::warn!(
                "Error fetching CoinGecko price for {}-{}: {}",
                from_symbol,
                to_symbol,
                e
            );
        }
    }

    if count > 0 {
        let average_price = sum / count as f64;
        let mut data = price_data.lock().unwrap();
        *data = PriceData {
            price: average_price,
            timestamp: Utc::now().timestamp(),
            sources,
        };
        log::info!(
            "Price updated for {}-{}: {} (from {} sources)",
            from_symbol,
            to_symbol,
            average_price,
            count
        );
    } else {
        log::error!(
            "Failed to fetch price data for {}-{} from all sources",
            from_symbol,
            to_symbol
        );
    }
}

pub async fn init_price_feed(from_symbol: &str, to_symbol: &str) -> Arc<Mutex<PriceData>> {
    let price_data = Arc::new(Mutex::new(PriceData::default()));

    // Initial fetch
    update_price_data_for_pair(from_symbol, to_symbol, price_data.clone()).await;

    let price_data_clone = price_data.clone();
    let from_symbol_clone = from_symbol.to_string();
    let to_symbol_clone = to_symbol.to_string();

    // Update every 60 seconds (1 minute)
    tokio::spawn(async move {
        let mut interval = time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            update_price_data_for_pair(
                &from_symbol_clone,
                &to_symbol_clone,
                price_data_clone.clone(),
            )
            .await;
        }
    });

    log::info!(
        "{}-{} price feed initialized and updating every 60 seconds",
        from_symbol,
        to_symbol
    );
    price_data
}

pub fn get_current_rate(price_data: Arc<Mutex<PriceData>>) -> Result<f64> {
    let data = price_data
        .lock()
        .map_err(|_| anyhow!("Failed to acquire price data lock"))?;

    if data.price <= 0.0 {
        return Err(anyhow!("No valid price data available"));
    }

    Ok(data.price)
}

pub fn get_exchange_rate(from_symbol: &str, to_symbol: &str, cache: &PriceCache) -> Result<f64> {
    let pair_key = format!("{}-{}", from_symbol, to_symbol);

    if let Some(price_data) = cache.get_price_data(&pair_key) {
        return get_current_rate(price_data);
    }

    Err(anyhow!(
        "Price feed not initialized for {}-{}",
        from_symbol,
        to_symbol
    ))
}
