use anyhow::{anyhow, Ok, Result};
use rand::Rng;
use starknet::core::{crypto::compute_hash_on_elements, types::Felt};

pub struct PoseidonHasher;

impl PoseidonHasher {
    pub fn hash_single(value: Felt) -> Felt {
        compute_hash_on_elements(&[value])
    }

    pub fn hash_many(values: &[Felt]) -> Felt {
        compute_hash_on_elements(values)
    }

    pub fn hash_string(s: &str) -> Result<Felt> {
        let felt = Felt::from_hex(s).or_else(|_| {
            let bytes = s.as_bytes();
            if bytes.len() > 31 {
                return Err(anyhow!("String too long for single Felt"));
            }
            let mut padded = [0u8; 32];
            padded[32 - bytes.len()..].copy_from_slice(bytes);
            Ok(Felt::from_bytes_be(&padded))
        })?;
        Ok(Self::hash_single(felt))
    }

    pub fn generate_hash_lock(secret: &str) -> Result<String> {
        let secret_felt = Felt::from_hex(secret)?;
        let hash_lock = Self::hash_single(secret_felt);
        Ok(format!("0x{:064x}", hash_lock))
    }

    pub fn generate_commitment(amount: &str, blinding_factor: &str) -> Result<String> {
        let amount_felt = Felt::from_hex(amount)?;
        let blinding_felt = Felt::from_hex(blinding_factor)?;

        let commitment = compute_hash_on_elements(&[amount_felt, blinding_felt]);
        Ok(format!("0x{:064x}", commitment))
    }

    pub fn generate_nullifier(commitment: &str, secret: &str) -> Result<String> {
        let commitment_felt = Felt::from_hex(commitment)?;
        let secret_felt = Felt::from_hex(secret)?;

        let nullifier = compute_hash_on_elements(&[commitment_felt, secret_felt]);
        Ok(format!("0x{:064x}", nullifier))
    }

    pub fn generate_random_felt() -> Felt {
        let mut rng = rand::rng();
        let random_bytes: [u8; 32] = rng.random();
        Felt::from_bytes_be(&random_bytes)
    }

    pub fn bytes_to_felt(bytes: &[u8]) -> Result<Felt> {
        if bytes.len() > 32 {
            return Err(anyhow!("Bytes too long for Felt"));
        }
        let mut padded = [0u8; 32];
        padded[32 - bytes.len()..].copy_from_slice(bytes);
        Ok(Felt::from_bytes_be(&padded))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_single() {
        let value = Felt::from_hex("0x1234").unwrap();
        let hash = PoseidonHasher::hash_single(value);
        assert_ne!(hash, value);
    }

    #[test]
    fn test_generate_commitment() {
        let amount = "0x64"; // 100
        let blinding = "0x123456";
        let commitment = PoseidonHasher::generate_commitment(amount, blinding).unwrap();
        assert!(commitment.starts_with("0x"));
        assert_eq!(commitment.len(), 66); // 0x + 64 hex chars
    }

    #[test]
    fn test_generate_nullifier() {
        let commitment = "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let secret = "0x123456";
        let nullifier = PoseidonHasher::generate_nullifier(commitment, secret).unwrap();
        assert!(nullifier.starts_with("0x"));
        assert_eq!(nullifier.len(), 66);
    }

    #[test]
    fn test_hash_lock_generation() {
        let secret = "0x987654321";
        let hash_lock = PoseidonHasher::generate_hash_lock(secret).unwrap();
        assert!(hash_lock.starts_with("0x"));

        // Verify it's deterministic
        let hash_lock2 = PoseidonHasher::generate_hash_lock(secret).unwrap();
        assert_eq!(hash_lock, hash_lock2);
    }
}
