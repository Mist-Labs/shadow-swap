use anyhow::{Ok, Result, anyhow};
use rs_merkle::{Hasher, MerkleTree as RsMerkleTree};
use starknet::core::types::Felt;
use std::collections::HashMap;

use crate::crypto::{
    model::{AnonymitySetManager, CommitmentMerkleTree, MembershipProof},
    poseidon::PoseidonHasher,
};

#[derive(Clone)]
pub struct PoseidonMerkleHasher;

impl Hasher for PoseidonMerkleHasher {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> Self::Hash {
        let left_bytes: [u8; 32] = data[0..32]
            .try_into()
            .expect("Slice length mismatch for left hash");
        let right_bytes: [u8; 32] = data[32..64]
            .try_into()
            .expect("Slice length mismatch for right hash");

        let left_felt = Felt::from_bytes_be(&left_bytes);
        let right_felt = Felt::from_bytes_be(&right_bytes);

        let inputs = [left_felt, right_felt];
        let hash = crate::crypto::poseidon::PoseidonHasher::hash_many(&inputs);

        hash.to_bytes_be()
    }
}

impl CommitmentMerkleTree {
    pub fn new(depth: usize) -> Self {
        if depth > 32 {
            panic!("Merkle tree depth cannot exceed 32");
        }

        Self {
            root: String::new(),
            depth,
            leaf_count: 0,
            commitments: Vec::new(),
            commitment_to_index: HashMap::new(),
        }
    }

    pub fn add_commitment(&mut self, commitment: &str) -> Result<usize> {
        if !commitment.starts_with("0x") {
            return Err(anyhow!("Invalid commitment format"));
        }

        if commitment.len() != 66 {
            return Err(anyhow!("Invalid commitment length"));
        }

        if self.commitment_to_index.contains_key(commitment) {
            return Err(anyhow!("Commitment already exists in tree"));
        }

        let max_leaves = 1usize << self.depth;
        if self.leaf_count >= max_leaves {
            return Err(anyhow!("Merkle tree is full"));
        }

        let index = self.leaf_count;
        self.commitments.push(commitment.to_string());
        self.commitment_to_index
            .insert(commitment.to_string(), index);
        self.leaf_count += 1;

        self.rebuild()?;

        Ok(index)
    }

    pub fn add_commitments(&mut self, commitments: &[String]) -> Result<Vec<usize>> {
        let max_leaves = 1usize << self.depth;
        if self.leaf_count + commitments.len() > max_leaves {
            return Err(anyhow!("Not enough space in tree"));
        }

        let mut indices = Vec::with_capacity(commitments.len());

        for commitment in commitments {
            let index = self.add_commitment(commitment)?;
            indices.push(index);
        }

        Ok(indices)
    }

    fn rebuild(&mut self) -> Result<()> {
        if self.commitments.is_empty() {
          let zero_leaf = Felt::ZERO.to_bytes_be();
            let tree = RsMerkleTree::<PoseidonMerkleHasher>::from_leaves(&[zero_leaf]);

            if let Some(root_bytes) = tree.root() {
                let root_felt = Felt::from_bytes_be(&root_bytes);
                self.root = format!("0x{:064x}", root_felt);
            } else {
                self.root = "0x0000000000000000000000000000000000000000000000000000000000000000"
                    .to_string();
            }

            return Ok(());
        }

        let leaves: Vec<[u8; 32]> = self
            .commitments
            .iter()
            .map(|c| {
                let felt = Felt::from_hex(c).unwrap_or(Felt::ZERO);
                felt.to_bytes_be()
            })
            .collect();

        let tree = RsMerkleTree::<PoseidonMerkleHasher>::from_leaves(&leaves);

        let root_bytes = tree
            .root()
            .ok_or_else(|| anyhow!("Failed to compute root"))?;
        let root_felt = Felt::from_bytes_be(&root_bytes);
        self.root = format!("0x{:064x}", root_felt);

        Ok(())
    }

    pub fn generate_proof(&self, commitment: &str) -> Result<MembershipProof> {
        let index = self
            .commitment_to_index
            .get(commitment)
            .ok_or_else(|| anyhow!("Commitment not in tree"))?;

        if self.commitments.is_empty() {
            return Err(anyhow!("Cannot generate proof for empty tree"));
        }

        let leaves: Vec<[u8; 32]> = self
            .commitments
            .iter()
            .map(|c| {
                let felt = Felt::from_hex(c).unwrap_or(Felt::ZERO);
                felt.to_bytes_be()
            })
            .collect();

        let tree = RsMerkleTree::<PoseidonMerkleHasher>::from_leaves(&leaves);
        let proof = tree.proof(&[*index]);

        let proof_hashes: Vec<String> = proof
            .proof_hashes()
            .iter()
            .map(|hash| {
                let felt = Felt::from_bytes_be(hash);
                format!("0x{:064x}", felt)
            })
            .collect();

        let mut indices = Vec::new();
        let mut current_index = *index;

        for _ in 0..proof_hashes.len() {
            indices.push(current_index % 2);
            current_index /= 2;
        }

        Ok(MembershipProof {
            root: self.root.clone(),
            leaf: commitment.to_string(),
            leaf_index: *index,
            path: proof_hashes,
            indices,
        })
    }

    pub fn verify_proof(proof: &MembershipProof) -> Result<bool> {
        let mut current_hash = Felt::from_hex(&proof.leaf)?;

        for (i, sibling_hex) in proof.path.iter().enumerate() {
            let sibling = Felt::from_hex(sibling_hex)?;
            let position = proof
                .indices
                .get(i)
                .ok_or_else(|| anyhow!("Missing index"))?;

            let inputs = if *position == 0 {
                [current_hash, sibling]
            } else {
                [sibling, current_hash]
            };

            current_hash = crate::crypto::poseidon::PoseidonHasher::hash_many(&inputs);
        }

        let computed_root = format!("0x{:064x}", current_hash);
        Ok(computed_root == proof.root)
    }

    pub fn get_root(&self) -> &str {
        &self.root
    }

    pub fn size(&self) -> usize {
        self.leaf_count
    }

    pub fn contains(&self, commitment: &str) -> bool {
        self.commitment_to_index.contains_key(commitment)
    }

    pub fn get_commitment(&self, index: usize) -> Option<&String> {
        self.commitments.get(index)
    }

    #[cfg(test)]
    pub fn get_all_commitments(&self) -> &[String] {
        &self.commitments
    }
}

impl MembershipProof {
    pub fn to_contract_format(&self) -> Vec<String> {
        let mut result = vec![
            self.root.clone(),
            self.leaf.clone(),
            format!("0x{:x}", self.leaf_index),
        ];
        result.extend(self.path.clone());
        result
    }

    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|e| anyhow!("Serialization failed: {}", e))
    }

    pub fn from_json(json: &str) -> Result<Self> {
        serde_json::from_str(json).map_err(|e| anyhow!("Deserialization failed: {}", e))
    }
}

impl AnonymitySetManager {
    pub fn new(default_depth: usize) -> Self {
        Self {
            trees: HashMap::new(),
            default_depth,
        }
    }

    pub fn get_or_create_tree(&mut self, token_address: &str) -> &mut CommitmentMerkleTree {
        self.trees
            .entry(token_address.to_string())
            .or_insert_with(|| CommitmentMerkleTree::new(self.default_depth))
    }

    pub fn add_commitment(
        &mut self,
        token_address: &str,
        commitment: &str,
    ) -> Result<(usize, String)> {
        let tree = self.get_or_create_tree(token_address);
        let index = tree.add_commitment(commitment)?;
        let root = tree.get_root().to_string();
        Ok((index, root))
    }

    pub fn generate_proof(&self, token_address: &str, commitment: &str) -> Result<MembershipProof> {
        let tree = self
            .trees
            .get(token_address)
            .ok_or_else(|| anyhow!("No tree for token"))?;
        tree.generate_proof(commitment)
    }

    pub fn get_root(&self, token_address: &str) -> Option<String> {
        self.trees
            .get(token_address)
            .map(|t| t.get_root().to_string())
    }

    pub fn get_set_size(&self, token_address: &str) -> usize {
        self.trees.get(token_address).map(|t| t.size()).unwrap_or(0)
    }

    pub fn get_tree(&self, token_address: &str) -> Option<&CommitmentMerkleTree> {
        self.trees.get(token_address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree_basic() {
        let mut tree = CommitmentMerkleTree::new(20);

        let commitment1 = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let commitment2 = "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";

        let idx1 = tree.add_commitment(commitment1).unwrap();
        let idx2 = tree.add_commitment(commitment2).unwrap();

        assert_eq!(idx1, 0);
        assert_eq!(idx2, 1);
        assert_eq!(tree.size(), 2);
        assert!(!tree.get_root().is_empty());
    }

    #[test]
    fn test_membership_proof() {
        let mut tree = CommitmentMerkleTree::new(20);

        let commitment = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        tree.add_commitment(commitment).unwrap();

        let proof = tree.generate_proof(commitment).unwrap();
        let is_valid = CommitmentMerkleTree::verify_proof(&proof).unwrap();

        assert!(is_valid, "Proof should be valid");
        assert_eq!(proof.root, tree.get_root());
        assert_eq!(proof.leaf, commitment);
        assert_eq!(proof.leaf_index, 0);
    }

    #[test]
    fn test_duplicate_rejection() {
        let mut tree = CommitmentMerkleTree::new(20);

        let commitment = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        tree.add_commitment(commitment).unwrap();

        let result = tree.add_commitment(commitment);
        assert!(result.is_err());
    }

    #[test]
    fn test_anonymity_set_manager() {
        let mut manager = AnonymitySetManager::new(20);

        let token1 = "0xaaaa";
        let token2 = "0xbbbb";

        let commitment1 = "0x1111111111111111111111111111111111111111111111111111111111111111";
        let commitment2 = "0x2222222222222222222222222222222222222222222222222222222222222222";

        let (idx1, root1) = manager.add_commitment(token1, commitment1).unwrap();
        let (idx2, root2) = manager.add_commitment(token2, commitment2).unwrap();

        assert_eq!(idx1, 0);
        assert_eq!(idx2, 0);
        assert_ne!(root1, root2);

        assert_eq!(manager.get_set_size(token1), 1);
        assert_eq!(manager.get_set_size(token2), 1);
    }

    #[test]
    fn test_proof_serialization() {
        let mut tree = CommitmentMerkleTree::new(20);
        let commitment = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        tree.add_commitment(commitment).unwrap();

        let proof = tree.generate_proof(commitment).unwrap();
        let json = proof.to_json().unwrap();
        let deserialized = MembershipProof::from_json(&json).unwrap();

        assert_eq!(proof.root, deserialized.root);
        assert_eq!(proof.leaf, deserialized.leaf);
        assert_eq!(proof.leaf_index, deserialized.leaf_index);
    }

    #[test]
    fn test_multiple_commitments() {
        let mut tree = CommitmentMerkleTree::new(20);

        let commitments = vec![
            "0x1111111111111111111111111111111111111111111111111111111111111111".to_string(),
            "0x2222222222222222222222222222222222222222222222222222222222222222".to_string(),
            "0x3333333333333333333333333333333333333333333333333333333333333333".to_string(),
        ];

        let indices = tree.add_commitments(&commitments).unwrap();
        assert_eq!(indices, vec![0, 1, 2]);

        tree.add_commitment("0x4444444444444444444444444444444444444444444444444444444444444444")
            .unwrap();

        for commitment in &commitments {
            let proof = tree.generate_proof(commitment).unwrap();
            let is_valid = CommitmentMerkleTree::verify_proof(&proof).unwrap();
            assert!(
                is_valid,
                "Proof for commitment {} should be valid",
                commitment
            );
        }
    }

    #[test]
    fn test_verify_proof_invalid() {
        let mut tree1 = CommitmentMerkleTree::new(20);
        let commitment1 = "0x1111111111111111111111111111111111111111111111111111111111111111";
        let commitment1_extra =
            "0xaaaa111111111111111111111111111111111111111111111111111111111111";
        tree1.add_commitment(commitment1).unwrap();
        tree1.add_commitment(commitment1_extra).unwrap();

        let valid_proof = tree1.generate_proof(commitment1).unwrap();

        // 1. Invalid Root Test (OK)
        let mut invalid_root_proof = valid_proof.clone();
        invalid_root_proof.root =
            "0x000000000000000000000000000000000000000000000000000000000000dead".to_string();
        let is_valid = CommitmentMerkleTree::verify_proof(&invalid_root_proof).unwrap();
        assert!(!is_valid, "Proof with invalid root should be rejected");

        // 2. Invalid Leaf Test (OK)
        let invalid_leaf =
            "0x9999999999999999999999999999999999999999999999999999999999999999".to_string();
        let mut invalid_leaf_proof = valid_proof.clone();
        invalid_leaf_proof.leaf = invalid_leaf;
        let is_valid = CommitmentMerkleTree::verify_proof(&invalid_leaf_proof).unwrap();
        assert!(!is_valid, "Proof with wrong leaf should be rejected");

        // 3. Invalid Path Test (OK)
        let mut invalid_path_proof = valid_proof.clone();
        if let Some(hash) = invalid_path_proof.path.get_mut(0) {
            *hash =
                "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".to_string();
        }
        let is_valid = CommitmentMerkleTree::verify_proof(&invalid_path_proof).unwrap();
        assert!(!is_valid, "Proof with tampered path should be rejected");

        // 4. Mismatched Tree Test (CRITICAL FIX: Ensure tree2 also has a non-trivial root)
        let mut tree2 = CommitmentMerkleTree::new(20);
        let commitment2 = "0x2222222222222222222222222222222222222222222222222222222222222222";
        let commitment2_extra =
            "0xbbbb222222222222222222222222222222222222222222222222222222222222";
        tree2.add_commitment(commitment2).unwrap();
        tree2.add_commitment(commitment2_extra).unwrap(); 

        let root2 = tree2.get_root().to_string();
        let mut mismatched_tree_proof = valid_proof.clone();
        mismatched_tree_proof.root = root2;
        let is_valid = CommitmentMerkleTree::verify_proof(&mismatched_tree_proof).unwrap();
        assert!(
            !is_valid,
            "Proof from one tree should not verify against another tree's root"
        );
    }
}
