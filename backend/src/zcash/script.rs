use std::time::{SystemTime, UNIX_EPOCH};


use sha2::{Digest, Sha256};

use crate::zcash::indexer::model::{HTLCState, ZcashHTLC};


impl ZcashHTLC {
    pub fn new(hash_lock: String, timelock: u64, recipient: String, amount: f64) -> Self {
        Self {
            version: 1,
            hash_lock,
            timelock,
            recipient,
            amount,
            state: HTLCState::Pending,
        }
    }

    pub fn encode_memo(&self) -> Result<String, String> {
        let data = format!(
            "HTLC:v{}:hl:{}:tl:{}:amt:{}",
            self.version, self.hash_lock, self.timelock, self.amount
        );

        if data.len() > 500 {
            return Err("HTLC data exceeds memo limit".to_string());
        }

        Ok(hex::encode(data.as_bytes()))
    }

    pub fn decode_memo(memo_hex: &str, recipient: &str) -> Result<Self, String> {
        let bytes = hex::decode(memo_hex).map_err(|e| e.to_string())?;
        let data = String::from_utf8(bytes).map_err(|e| e.to_string())?;

        let parts: Vec<&str> = data.split(':').collect();
        if parts.len() < 8 || parts[0] != "HTLC" {
            return Err("Invalid HTLC memo format".to_string());
        }

        let version = parts[1]
            .trim_start_matches('v')
            .parse()
            .map_err(|_| "Invalid version")?;
        let hash_lock = parts[3].to_string();
        let timelock = parts[5].parse().map_err(|_| "Invalid timelock")?;
        let amount = parts[7].parse().map_err(|_| "Invalid amount")?;

        Ok(Self {
            version,
            hash_lock,
            timelock,
            recipient: recipient.to_string(),
            amount,
            state: HTLCState::Pending,
        })
    }

    pub fn verify_secret(&self, secret: &str) -> bool {
        let mut hasher = Sha256::new();
        hasher.update(secret.as_bytes());
        let computed_hash = hex::encode(hasher.finalize());

        computed_hash == self.hash_lock ||
        format!("0x{}", computed_hash) == self.hash_lock
    }

    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        now >= self.timelock
    }

    pub fn can_redeem(&self, secret: &str) -> Result<(), String> {
        if self.state != HTLCState::Pending {
            return Err(format!("HTLC not in pending state: {:?}", self.state));
        }

        if self.is_expired() {
            return Err("HTLC expired".to_string());
        }

        if !self.verify_secret(secret) {
            return Err("Invalid secret".to_string());
        }

        Ok(())
    }

    pub fn can_refund(&self) -> Result<(), String> {
        if self.state != HTLCState::Pending {
            return Err(format!("HTLC not in pending state: {:?}", self.state));
        }

        if !self.is_expired() {
            return Err(format!(
                "HTLC not yet expired. Expires at: {}",
                self.timelock
            ));
        }

        Ok(())
    }

    pub fn can_redeem_memo(secret: &str) -> String {
        let data = format!("REDEEM:{}", secret);
        hex::encode(data.as_bytes())
    }

    pub fn create_refund_memo(reason: &str) -> String {
        let data = format!("REFUND:{}", reason);
        hex::encode(data.as_bytes())
    }
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_htlc_creation() {
        let htlc = ZcashHTLC::new(
            "abc123".to_string(),
            1700000000,
            "zs1test...".to_string(),
            1.5,
        );

        assert_eq!(htlc.version, 1);
        assert_eq!(htlc.state, HTLCState::Pending);
    }

    #[test]
    fn test_memo_encoding_decoding() {
        let htlc = ZcashHTLC::new(
            "deadbeef".to_string(),
            1700000000,
            "zs1test...".to_string(),
            2.5,
        );

        let memo = htlc.encode_memo().unwrap();
        assert!(!memo.is_empty());

        let decoded = ZcashHTLC::decode_memo(&memo, "zs1test...").unwrap();
        assert_eq!(decoded.hash_lock, htlc.hash_lock);
        assert_eq!(decoded.timelock, htlc.timelock);
        assert_eq!(decoded.amount, htlc.amount);
    }

    #[test]
    fn test_secret_verification() {
        let secret = "my_secret_123";
        let mut hasher = Sha256::new();
        hasher.update(secret.as_bytes());
        let hash_lock = hex::encode(hasher.finalize());

        let htlc = ZcashHTLC::new(
            hash_lock,
            1700000000,
            "zs1test...".to_string(),
            1.0,
        );

        assert!(htlc.verify_secret(secret));
        assert!(!htlc.verify_secret("wrong_secret"));
    }

    #[test]
    fn test_expiration() {
        let past_timelock = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() - 3600;

        let htlc = ZcashHTLC::new(
            "hash".to_string(),
            past_timelock,
            "zs1test...".to_string(),
            1.0,
        );

        assert!(htlc.is_expired());
    }

    #[test]
    fn test_redemption_validation() {
        let secret = "valid_secret";
        let mut hasher = Sha256::new();
        hasher.update(secret.as_bytes());
        let hash_lock = hex::encode(hasher.finalize());

        let future_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() + 3600;

        let htlc = ZcashHTLC::new(
            hash_lock,
            future_time,
            "zs1test...".to_string(),
            1.0,
        );

        assert!(htlc.can_redeem(secret).is_ok());
        assert!(htlc.can_refund().is_err());
    }
}