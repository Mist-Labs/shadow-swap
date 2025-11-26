use std::collections::HashMap;

use bulletproofs::{BulletproofGens, PedersenGens};
use serde::{Deserialize, Serialize};



#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AmountRangeProof {
    pub proof: Vec<u8>,
    pub commitment: Vec<u8>,
    pub bit_size: usize,
}

pub struct RangeProofGenerator {
    bp_gens: BulletproofGens,
    pc_gens: PedersenGens,
}

pub struct StwoRangeProof {
    pub commitment: String,
    pub proof_data: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitmentMerkleTree {
    pub root: String,
    pub depth: usize,
    pub leaf_count: usize,
    #[serde(skip)]
    pub commitments: Vec<String>,
    #[serde(skip)]
    pub commitment_to_index: HashMap<String, usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MembershipProof {
    pub root: String,
    pub leaf: String,
    pub leaf_index: usize,
    pub path: Vec<String>,
    pub indices: Vec<usize>,
}

pub struct AnonymitySetManager {
    pub trees: HashMap<String, CommitmentMerkleTree>,
    pub default_depth: usize,
}