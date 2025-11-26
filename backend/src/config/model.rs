use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RelayerConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub starknet: StarknetConfig,
    pub zcash: ZcashConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub hmac_secret: String
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub max_connections: u32,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct StarknetConfig {
    pub rpc_url: String,
    pub fast_pool_address: String,
    pub standard_pool_address: String,
    pub owner_address: String,
    pub owner_private_key: String,
    pub chain_id: String,
    pub token_address: String
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ZcashConfig {
    pub rpc_url: String,
    pub rpc_user: String,
    pub rpc_password: String,
    pub wallet_name: String,
    pub pool_address: String
}
