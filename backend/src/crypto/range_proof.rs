// NOT USED FOR NOW, WORK STILL UNDERWAY TO FULL INTEGRATION
// USING MERKLE BASED PRIVACY FOR NOW

use anyhow::{Ok, Result, anyhow};
use serde::{Deserialize, Serialize};
use starknet::core::types::Felt;
use stwo::core::{fields::m31::BaseField, vcs::blake2_merkle::Blake2sMerkleChannel};

use crate::crypto::{model::StwoRangeProof, poseidon::PoseidonHasher};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmountRangeProof {
    pub bit_commitments: Vec<String>,
    pub proof_elements: Vec<String>,
    pub bit_size: usize,
}

pub struct RangeProofGenerator;

impl RangeProofGenerator {
    pub fn generate(
        amount: u64,
        blinding_seed: &str,
        bit_size: usize,
    ) -> Result<AmountRangeProof> {
        if bit_size == 0 {
            return Err(anyhow!("Bit size must be greater than 0"));
        }

        if bit_size > 64 {
            return Err(anyhow!("Bit size cannot exceed 64 for u64 values"));
        }

        if !Self::validate_bit_size(amount, bit_size) {
            return Err(anyhow!(
                "Amount {} does not fit in {} bits",
                amount,
                bit_size
            ));
        }

        let blinding_seed_felt = Felt::from_hex(blinding_seed)?;
        let mut bit_commitments = Vec::with_capacity(bit_size);
        let mut proof_elements = Vec::with_capacity(bit_size);

        for i in 0..bit_size {
            let bit = (amount >> i) & 1;

            let bit_blinding =
                PoseidonHasher::hash_many(&[blinding_seed_felt, Felt::from(i as u64)]);

            let bit_commitment = PoseidonHasher::hash_many(&[Felt::from(bit), bit_blinding]);

            bit_commitments.push(format!("0x{:064x}", bit_commitment));

            let proof_elem =
                PoseidonHasher::hash_many(&[Felt::from(bit), Felt::from(1 - bit), bit_blinding]);

            proof_elements.push(format!("0x{:064x}", proof_elem));
        }

        Ok(AmountRangeProof {
            bit_commitments,
            proof_elements,
            bit_size,
        })
    }

    pub fn validate_bit_size(value: u64, bits: usize) -> bool {
        if bits >= 64 {
          
            return true;
        }
        
        if bits == 0 {
            return value == 0;
        }
        
        let max_value = (1u64 << bits) - 1;
        value <= max_value
    }

    pub fn verify(
        proof: &AmountRangeProof,
        amount_commitment: &str,
        blinding_seed: &str,
    ) -> Result<bool> {
        if proof.bit_commitments.len() != proof.proof_elements.len() {
            return Ok(false);
        }

        if proof.bit_commitments.len() != proof.bit_size {
            return Ok(false);
        }

         let blinding_seed_felt = Felt::from_hex(blinding_seed)?;

        let mut reconstructed_amount = Felt::ZERO;
        let mut power_of_two = Felt::ONE;

        for i in 0..proof.bit_commitments.len() {
            let bit_blinding =
                PoseidonHasher::hash_many(&[blinding_seed_felt, Felt::from(i as u64)]);

            let mut bit_found = false;

            for bit_val in [0u64, 1u64] {
                let expected_commitment =
                    PoseidonHasher::hash_many(&[Felt::from(bit_val), bit_blinding]);

                let actual_commitment = Felt::from_hex(&proof.bit_commitments[i])?;
                if expected_commitment == actual_commitment {
                    if bit_val == 1 {
                        reconstructed_amount = reconstructed_amount + power_of_two;
                    }
                    bit_found = true;
                    break;
                }
            }

            if !bit_found {
                return Ok(false);
            }

            power_of_two = power_of_two + power_of_two;
        }

        let expected_commitment = PoseidonHasher::generate_commitment(
            &format!("0x{:x}", reconstructed_amount),
            blinding_seed,
        )?;

        Ok(expected_commitment == amount_commitment)
    }

    pub fn generate_batch(
        amounts: &[u64],
        blinding_seeds: &[String],
        bit_size: usize,
    ) -> Result<Vec<AmountRangeProof>> {
        if amounts.len() != blinding_seeds.len() {
            return Err(anyhow!("Amounts and blinding seeds length mismatch"));
        }

        amounts
            .iter()
            .zip(blinding_seeds.iter())
            .map(|(amount, seed)| Self::generate(*amount, seed, bit_size))
            .collect()
    }
}

pub struct StwoProofGenerator;

impl StwoProofGenerator {
    pub fn generate_zk_proof(
        amount: u64,
        blinding_factor: &str,
        bit_size: usize,
    ) -> Result<StwoRangeProof> {
        if bit_size > 64 {
            return Err(anyhow!("Bit size cannot exceed 64"));
        }

        let commitment =
            PoseidonHasher::generate_commitment(&format!("0x{:x}", amount), blinding_factor)?;

        let mut channel = Blake2sMerkleChannel::default();

        let mut bit_values = Vec::with_capacity(bit_size);
        for i in 0..bit_size {
            let bit = ((amount >> 1) & 1) as u32;
            bit_values.push(BaseField::from_u32_unchecked(bit));
        }

        // Generate proof that each bit is 0 or 1 and they sum to the amount
        // This is a simplified version - full implementation would use Stwo's AIR

        let proof_data = Self::serialize_proof_data(&bit_values, &commitment)?;

        Ok(StwoRangeProof {
            commitment,
            proof_data,
        })
    }

    fn serialize_proof_data(bit_values: &[BaseField], commitment: &str) -> Result<Vec<u8>> {
        let mut data = Vec::new();

        data.extend_from_slice(commitment.as_bytes());

        data.extend_from_slice(&(bit_values.len() as u32).to_le_bytes());

        let mut byte_packed = 0u8;
        let mut bit_pos = 0;

        for bit in bit_values {
            let bit_val = if bit.0 == 0 { 0u8 } else { 1u8 };
            byte_packed |= bit_val << bit_pos;
            bit_pos += 1;

            if bit_pos == 8 {
                data.push(byte_packed);
                byte_packed = 0;
                bit_pos = 0;
            }
        }

        if bit_pos > 0 {
            data.push(byte_packed);
        }

        Ok(data)
    }

    pub fn verify_zk_proof(proof: &StwoRangeProof) -> bool {
        // Validate the proof structure
        if proof.proof_data.len() < 66 {
            return Ok(false).unwrap();
        }

        if !proof.commitment.starts_with("0x") {
            return Ok(false).unwrap();
        }

        // Validate commitment format
        if proof.commitment.len() != 66 {
            return Ok(false).unwrap();
        }

        Ok(true).unwrap()
    }
}

/* 
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_range_proof_generation() {
        let amount = 1000u64;
        let blinding_seed = "0x123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        
        let proof = RangeProofGenerator::generate(amount, blinding_seed, 16).unwrap();
        
        assert_eq!(proof.bit_commitments.len(), 16);
        assert_eq!(proof.proof_elements.len(), 16);
        assert_eq!(proof.bit_size, 16);
    }

    #[test]
    fn test_range_proof_verification() {
        let amount = 1000u64;
        let blinding_seed = "0x123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        
        let proof = RangeProofGenerator::generate(amount, blinding_seed, 16).unwrap();
        
        let commitment = PoseidonHasher::generate_commitment(
            &format!("0x{:x}", amount),
            blinding_seed,
        ).unwrap();
        
        let is_valid = RangeProofGenerator::verify(&proof, &commitment, blinding_seed).unwrap();
        assert!(is_valid);
    }

    
    #[test]
    fn test_invalid_proof_rejection() {
        let amount = 1000u64;
        let blinding_seed = "0x123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        
        let proof = RangeProofGenerator::generate(amount, blinding_seed, 16).unwrap();
        
        // Try to verify with wrong commitment
        let wrong_commitment = "0x0000000000000000000000000000000000000000000000000000000000000000";
        
        let is_valid = RangeProofGenerator::verify(&proof, wrong_commitment, blinding_seed).unwrap();
        assert!(!is_valid);
    }

    #[test]
    fn test_batch_generation() {
        let amounts = vec![100u64, 200u64, 300u64];
        let seeds = vec![
            "0x1111111111111111111111111111111111111111111111111111111111111111".to_string(),
            "0x2222222222222222222222222222222222222222222222222222222222222222".to_string(),
            "0x3333333333333333333333333333333333333333333333333333333333333333".to_string(),
        ];

        let proofs = RangeProofGenerator::generate_batch(&amounts, &seeds, 16).unwrap();
        assert_eq!(proofs.len(), 3);

        for (i, proof) in proofs.iter().enumerate() {
            let commitment = PoseidonHasher::generate_commitment(
                &format!("0x{:x}", amounts[i]),
                &seeds[i],
            ).unwrap();
            
            let is_valid = RangeProofGenerator::verify(proof, &commitment, &seeds[i]).unwrap();
            assert!(is_valid);
        }
    }

    #[test]
    fn test_stwo_proof_generation() {
        let amount = 500u64;
        let blinding = "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        
        let proof = StwoProofGenerator::generate_zk_proof(amount, blinding, 32).unwrap();
        
        assert!(!proof.commitment.is_empty());
        assert!(!proof.proof_data.is_empty());
        assert!(proof.commitment.starts_with("0x"));
    }

    #[test]
    fn test_stwo_proof_verification() {
        let amount = 500u64;
        let blinding = "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        
        let proof = StwoProofGenerator::generate_zk_proof(amount, blinding, 32).unwrap();
        let is_valid = StwoProofGenerator::verify_zk_proof(&proof);
        
        assert!(is_valid);
    }

    #[test]
    fn test_bit_size_validation() {
        let amount = 100u64;
        let blinding = "0x123456";
        
        let result = RangeProofGenerator::generate(amount, blinding, 128);
        assert!(result.is_err());
    }
}

*/