use std::fmt::write;

use crate::models::models::{Chain, SwapStatus};

impl Chain {
    pub fn as_str(&self) -> &str {
        match self {
            Chain::Starknet => "starknet",
            Chain::Zcash => "zcash",
        }
    }
}

impl std::fmt::Display for Chain {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl SwapStatus {
    pub fn as_str(&self) -> &str {
        match self {
            SwapStatus::Initiated => "initiated",
            SwapStatus::Locked => "locked",
            SwapStatus::Redeemed => "redeemed",
            SwapStatus::Refunded => "refunded",
            SwapStatus::Failed => "failed",
        }
    }
}
