use std::{env, path::PathBuf};

use crate::config::model::{
    DatabaseConfig, RelayerConfig, ServerConfig, StarknetConfig, ZcashConfig,
};

impl RelayerConfig {
    pub fn from_file(path: PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        let contents = std::fs::read_to_string(path)?;
        let config: Self = toml::from_str(&contents)?;
        Ok(config)
    }

    pub fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        Ok(RelayerConfig {
            server: ServerConfig {
                host: std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
                port: std::env::var("PORT")
                    .unwrap_or_else(|_| "8080".to_string())
                    .parse()?,
                hmac_secret: std::env::var("HMAC_SECRET").expect("HMAC secret must be set")
            },
            database: DatabaseConfig {
                url: std::env::var("DATABASE_URL")?,
                max_connections: std::env::var("DB_MAX_CONNECTIONS")
                    .unwrap_or_else(|_| "10".to_string())
                    .parse()?,
            },
            starknet: StarknetConfig {
                rpc_url: env::var("STARKNET_RPC_URL")?,
                fast_pool_address: env::var("STARKNET_FAST_POOL_ADDRESS")?,
                standard_pool_address: env::var("STARKNET_STANDARD_POOL_ADDRESS")?,
                owner_address: env::var("OWNER_ADDRESS")?,
                owner_private_key: env::var("OWNER_PRIVATE_KEY")?,
                chain_id: env::var("CHAIN_ID")?,
                token_address: env::var("STARKNET_TOKEN_ADDRESS")?
            },
            zcash: ZcashConfig {
                rpc_url: std::env::var("ZCASH_RPC_URL")?,
                rpc_user: std::env::var("ZCASH_RPC_USER")?,
                rpc_password: std::env::var("ZCASH_RPC_PASSWORD")?,
                wallet_name: std::env::var("ZCASH_WALLET_NAME").unwrap_or_else(|_| "".to_string()),
                pool_address: std::env::var("ZCASH_POOL_ADDRESS")?
            },
        })
    }
}
