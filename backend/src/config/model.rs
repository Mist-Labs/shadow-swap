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
    pub hmac_secret: String,
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
    pub token_address: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ZcashConfig {
    pub network: String,
    pub rpc_url: String,
    pub rpc_user: String,
    pub rpc_password: String,
    pub database_url: String,
    pub database_max_connections: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub explorer_api: Option<String>,
    pub wallet_name: String,
    pub pool_address: String,
    pub private_key: String,
    pub token_address: String
}
