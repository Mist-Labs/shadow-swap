use std::sync::Arc;

use sha2::{Digest, Sha256};
use starknet::{
    accounts::{Account, ExecutionEncoding, SingleOwnerAccount},
    core::types::{Felt, TransactionReceipt},
    providers::{jsonrpc::HttpTransport, JsonRpcClient, Provider},
    signers::{LocalWallet, SigningKey},
};
use tokio::time::{sleep, Duration};
use tracing::{error, info, warn};

use crate::{
    config::model::StarknetConfig, database::database::Database, merkle_tree::model::PoolType,
};

#[derive(Debug, Clone)]
pub struct PrivacyParams {
    pub secret: String,
    pub hash_lock: String,
    pub blinding_factor: String,
    pub amount_commitment: String,
    pub ephemeral_pubkey: String,
    pub encrypted_data: String,
    pub bit_blinding_seed: String,
    pub range_proof: Vec<String>,
    pub stealth_initiator: String,
    pub stealth_participant: String,
}

pub struct StarknetRelayer {
    pub provider: Arc<JsonRpcClient<HttpTransport>>,
    pub account: SingleOwnerAccount<Arc<JsonRpcClient<HttpTransport>>, LocalWallet>,
    pub fast_pool_address: Felt,
    pub standard_pool_address: Felt,
    pub database: Arc<Database>,
}

impl StarknetRelayer {
    pub async fn new(
        config: StarknetConfig,
        database: Arc<Database>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        info!("🔗 Initializing Starknet relayer");

        let provider = Arc::new(JsonRpcClient::new(HttpTransport::new(url::Url::parse(
            &config.rpc_url,
        )?)));

        let fast_pool_address = Felt::from_hex(&config.fast_pool_address)?;
        let standard_pool_address = Felt::from_hex(&config.standard_pool_address)?;
        let controller_address = Felt::from_hex(&config.owner_address)?;

        let private_key =
            SigningKey::from_secret_scalar(Felt::from_hex(&config.owner_private_key)?);
        let signer = LocalWallet::from(private_key);
        let chain_id = provider.chain_id().await?;

        let account = SingleOwnerAccount::new(
            provider.clone(),
            signer,
            controller_address,
            chain_id,
            ExecutionEncoding::New,
        );

        Ok(Self {
            provider,
            account,
            fast_pool_address,
            standard_pool_address,
            database,
        })
    }

    pub fn generate_privacy_params(
        &self,
        user_address: &str,
        amount: &str,
        timestamp: i64,
    ) -> Result<PrivacyParams, Box<dyn std::error::Error>> {
        let seed = format!("{}:{}:{}", user_address, amount, timestamp);

        let mut hasher = Sha256::new();
        hasher.update(seed.as_bytes());
        hasher.update(b":secret");
        let secret = format!("0x{}", hex::encode(hasher.finalize()));

        let mut hasher = Sha256::new();
        hasher.update(secret.as_bytes());
        let hash_lock = format!("0x{}", hex::encode(hasher.finalize()));

        let mut hasher = Sha256::new();
        hasher.update(seed.as_bytes());
        hasher.update(b":blinding");
        let blinding_factor = format!("0x{}", hex::encode(hasher.finalize()));

        let mut hasher = Sha256::new();
        hasher.update(amount.as_bytes());
        hasher.update(blinding_factor.as_bytes());
        let amount_commitment = format!("0x{}", hex::encode(hasher.finalize()));

        let mut hasher = Sha256::new();
        hasher.update(seed.as_bytes());
        hasher.update(b":ephemeral");
        let ephemeral_pubkey = format!("0x{}", hex::encode(hasher.finalize()));

        let data_to_encrypt = format!("amount:{}|secret:{}", amount, secret);
        let mut hasher = Sha256::new();
        hasher.update(data_to_encrypt.as_bytes());
        hasher.update(ephemeral_pubkey.as_bytes());
        let encrypted_data = format!("0x{}", hex::encode(hasher.finalize()));

        let mut hasher = Sha256::new();
        hasher.update(seed.as_bytes());
        hasher.update(b":bit_blinding");
        let bit_blinding_seed = format!("0x{}", hex::encode(hasher.finalize()));

        let range_proof = self.generate_range_proof(&amount_commitment, &bit_blinding_seed);

        let mut hasher = Sha256::new();
        hasher.update(user_address.as_bytes());
        hasher.update(seed.as_bytes());
        hasher.update(b":stealth_initiator");
        let stealth_initiator = format!("0x{}", hex::encode(hasher.finalize()));

        let mut hasher = Sha256::new();
        hasher.update(b"relayer_pool");
        hasher.update(seed.as_bytes());
        hasher.update(b":stealth_participant");
        let stealth_participant = format!("0x{}", hex::encode(hasher.finalize()));

        Ok(PrivacyParams {
            secret,
            hash_lock,
            blinding_factor,
            amount_commitment,
            ephemeral_pubkey,
            encrypted_data,
            bit_blinding_seed,
            range_proof,
            stealth_initiator,
            stealth_participant,
        })
    }

    fn generate_range_proof(&self, commitment: &str, seed: &str) -> Vec<String> {
        (0..4)
            .map(|i| {
                let mut hasher = Sha256::new();
                hasher.update(commitment.as_bytes());
                hasher.update(seed.as_bytes());
                hasher.update(i.to_string().as_bytes());
                format!("0x{}", hex::encode(hasher.finalize()))
            })
            .collect()
    }

    pub async fn create_htlc(
        &self,
        token: &str,
        nullifier: &str,
        root: &str,
        commitment: &str,
        amount: u128,
        merkle_proof: Vec<String>,
        path_indices: Vec<u8>,
        hash_lock: &str,
        timelock: u64,
        pool_type: PoolType,
    ) -> Result<String, Box<dyn std::error::Error>> {
        info!("🔨 Creating HTLC in shielded pool");

        // Verify nullifier hasn't been spent
        let nullifier_spent = self.is_nullifier_spent(nullifier, pool_type).await?;
        if nullifier_spent {
            return Err("Nullifier already spent".into());
        }

        // Verify root is known in contract
        let is_known = self.is_root_known(root, pool_type).await?;
        if !is_known {
            return Err("Merkle root not known in contract".into());
        }

        let pool_address = match pool_type {
            PoolType::Fast => self.fast_pool_address,
            PoolType::Standard => self.standard_pool_address,
        };

        let token_felt = Felt::from_hex(token)?;
        let nullifier_felt = Felt::from_hex(nullifier)?;
        let root_felt = Felt::from_hex(root)?;
        let commitment_felt = Felt::from_hex(commitment)?;
        let amount_low = Felt::from(amount as u64);
        let amount_high = Felt::from((amount >> 64) as u64);
        let hash_lock_felt = Felt::from_hex(hash_lock)?;
        let timelock_felt = Felt::from(timelock);

        // Convert merkle proof to Felt vector
        let proof_felts: Result<Vec<Felt>, _> =
            merkle_proof.iter().map(|p| Felt::from_hex(p)).collect();
        let proof_felts = proof_felts?;

        // Convert path indices to Felt vector
        let indices_felts: Vec<Felt> = path_indices.iter().map(|&i| Felt::from(i)).collect();

        let mut calldata = vec![
            token_felt,
            nullifier_felt,
            root_felt,
            commitment_felt,
            amount_low,
            amount_high,
        ];

        // Span serialization: length followed by elements
        calldata.push(Felt::from(proof_felts.len()));
        calldata.extend(proof_felts);

        calldata.push(Felt::from(indices_felts.len()));
        calldata.extend(indices_felts);

        calldata.push(hash_lock_felt);
        calldata.push(timelock_felt);

        let call = starknet::core::types::Call {
            to: pool_address,
            selector: starknet::core::utils::get_selector_from_name("create_htlc")?,
            calldata,
        };

        let execution = self.account.execute_v3(vec![call]);
        let tx = execution.send().await?;

        info!(
            "📤 HTLC creation transaction sent: 0x{:x}",
            tx.transaction_hash
        );
        self.wait_for_transaction(tx.transaction_hash).await?;

        info!("✅ HTLC created with nullifier: {}", nullifier);
        Ok(format!("0x{:x}", tx.transaction_hash))
    }

    pub async fn redeem_htlc(
        &self,
        token: &str,
        nullifier: &str,
        recipient: &str,
        secret: &str,
        pool_type: PoolType,
    ) -> Result<String, Box<dyn std::error::Error>> {
        info!("🔓 Redeeming HTLC from shielded pool");

        let pool_address = match pool_type {
            PoolType::Fast => self.fast_pool_address,
            PoolType::Standard => self.standard_pool_address,
        };

        let token_felt = Felt::from_hex(token)?;
        let nullifier_felt = Felt::from_hex(nullifier)?;
        let recipient_felt = Felt::from_hex(recipient)?;
        let secret_felt = Felt::from_hex(secret)?;

        let call = starknet::core::types::Call {
            to: pool_address,
            selector: starknet::core::utils::get_selector_from_name("withdraw")?,
            calldata: vec![
                token_felt,
                nullifier_felt,
                recipient_felt,
                Felt::ONE,
                secret_felt,
            ],
        };

        let execution = self.account.execute_v3(vec![call]);
        let tx = execution.send().await?;

        info!("📤 Redeem transaction sent: 0x{:x}", tx.transaction_hash);
        self.wait_for_transaction(tx.transaction_hash).await?;

        Ok(format!("0x{:x}", tx.transaction_hash))
    }

    pub async fn refund_htlc(
        &self,
        token: &str,
        nullifier: &str,
        recipient: &str,
        pool_type: PoolType,
    ) -> Result<String, Box<dyn std::error::Error>> {
        info!("♻️ Refunding HTLC from shielded pool");

        let pool_address = match pool_type {
            PoolType::Fast => self.fast_pool_address,
            PoolType::Standard => self.standard_pool_address,
        };

        let token_felt = Felt::from_hex(token)?;
        let nullifier_felt = Felt::from_hex(nullifier)?;
        let recipient_felt = Felt::from_hex(recipient)?;

        let call = starknet::core::types::Call {
            to: pool_address,
            selector: starknet::core::utils::get_selector_from_name("withdraw")?,
            calldata: vec![token_felt, nullifier_felt, recipient_felt, Felt::ZERO],
        };

        let execution = self.account.execute_v3(vec![call]);
        let tx = execution.send().await?;

        info!("📤 Refund transaction sent: 0x{:x}", tx.transaction_hash);
        self.wait_for_transaction(tx.transaction_hash).await?;

        Ok(format!("0x{:x}", tx.transaction_hash))
    }

    pub async fn get_htlc(
        &self,
        nullifier: &str,
        pool_type: PoolType,
    ) -> Result<(String, String, String, u64, u8), Box<dyn std::error::Error>> {
        let pool_address = match pool_type {
            PoolType::Fast => self.fast_pool_address,
            PoolType::Standard => self.standard_pool_address,
        };

        let nullifier_felt = Felt::from_hex(nullifier)?;

        let result = self
            .provider
            .call(
                starknet::core::types::FunctionCall {
                    contract_address: pool_address,
                    entry_point_selector: starknet::core::utils::get_selector_from_name(
                        "get_htlc",
                    )?,
                    calldata: vec![nullifier_felt],
                },
                starknet::core::types::BlockId::Tag(starknet::core::types::BlockTag::PreConfirmed),
            )
            .await?;

        if result.len() < 5 {
            return Err("Invalid HTLC response".into());
        }

        let commitment = format!("0x{:x}", result[0]);
        let token = format!("0x{:x}", result[1]);
        let hash_lock = format!("0x{:x}", result[2]);
        let timelock = result[3].to_string().parse::<u64>()?;
        let state = result[4].to_string().parse::<u8>()?;

        Ok((commitment, token, hash_lock, timelock, state))
    }

    pub async fn is_root_known(
        &self,
        root: &str,
        pool_type: PoolType,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let pool_address = match pool_type {
            PoolType::Fast => self.fast_pool_address,
            PoolType::Standard => self.standard_pool_address,
        };

        let root_felt = Felt::from_hex(root)?;

        let result = self
            .provider
            .call(
                starknet::core::types::FunctionCall {
                    contract_address: pool_address,
                    entry_point_selector: starknet::core::utils::get_selector_from_name(
                        "is_known_root",
                    )?,
                    calldata: vec![root_felt],
                },
                starknet::core::types::BlockId::Tag(starknet::core::types::BlockTag::PreConfirmed),
            )
            .await?;

        if result.is_empty() {
            return Ok(false);
        }

        Ok(result[0] != Felt::ZERO)
    }

    pub async fn is_nullifier_spent(
        &self,
        nullifier: &str,
        pool_type: PoolType,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let pool_address = match pool_type {
            PoolType::Fast => self.fast_pool_address,
            PoolType::Standard => self.standard_pool_address,
        };

        let nullifier_felt = Felt::from_hex(nullifier)?;

        let result = self
            .provider
            .call(
                starknet::core::types::FunctionCall {
                    contract_address: pool_address,
                    entry_point_selector: starknet::core::utils::get_selector_from_name(
                        "is_nullifier_spent",
                    )?,
                    calldata: vec![nullifier_felt],
                },
                starknet::core::types::BlockId::Tag(starknet::core::types::BlockTag::PreConfirmed),
            )
            .await?;

        if result.is_empty() {
            return Ok(false);
        }

        Ok(result[0] != Felt::ZERO)
    }

    pub async fn get_current_root(
        &self,
        pool_type: PoolType,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let pool_address = match pool_type {
            PoolType::Fast => self.fast_pool_address,
            PoolType::Standard => self.standard_pool_address,
        };

        let result = self
            .provider
            .call(
                starknet::core::types::FunctionCall {
                    contract_address: pool_address,
                    entry_point_selector: starknet::core::utils::get_selector_from_name(
                        "get_current_root",
                    )?,
                    calldata: vec![],
                },
                starknet::core::types::BlockId::Tag(starknet::core::types::BlockTag::PreConfirmed),
            )
            .await?;

        if result.is_empty() {
            return Ok(String::new());
        }

        Ok(format!("0x{:064x}", result[0]))
    }

    pub async fn update_merkle_root(
        &self,
        new_root: &str,
        pool_type: PoolType,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let pool_name = match pool_type {
            PoolType::Fast => "Fast",
            PoolType::Standard => "Standard",
        };

        let pool_address = match pool_type {
            PoolType::Fast => self.fast_pool_address,
            PoolType::Standard => self.standard_pool_address,
        };

        info!(
            "🌳 Updating {} Pool merkle root on-chain: {}",
            pool_name, new_root
        );

        let root_felt = Felt::from_hex(new_root)?;

        let call = starknet::core::types::Call {
            to: pool_address,
            selector: starknet::core::utils::get_selector_from_name("update_merkle_root")?,
            calldata: vec![root_felt],
        };

        let execution = self.account.execute_v3(vec![call]);
        let tx = execution.send().await?;

        info!(
            "📤 {} Pool merkle root update transaction sent: 0x{:x}",
            pool_name, tx.transaction_hash
        );
        self.wait_for_transaction(tx.transaction_hash).await?;

        Ok(format!("0x{:x}", tx.transaction_hash))
    }

    async fn wait_for_transaction(
        &self,
        tx_hash: Felt,
    ) -> Result<TransactionReceipt, Box<dyn std::error::Error>> {
        info!("⏳ Waiting for transaction confirmation...");

        let mut attempts = 0;
        let max_attempts = 60;

        loop {
            attempts += 1;

            match self.provider.get_transaction_receipt(tx_hash).await {
                Ok(receipt_with_block) => {
                    let receipt = receipt_with_block.receipt;

                    let is_accepted = match &receipt {
                        TransactionReceipt::Invoke(r) => {
                            matches!(
                                r.execution_result,
                                starknet::core::types::ExecutionResult::Succeeded
                            )
                        }
                        TransactionReceipt::Declare(r) => {
                            matches!(
                                r.execution_result,
                                starknet::core::types::ExecutionResult::Succeeded
                            )
                        }
                        TransactionReceipt::DeployAccount(r) => {
                            matches!(
                                r.execution_result,
                                starknet::core::types::ExecutionResult::Succeeded
                            )
                        }
                        TransactionReceipt::Deploy(r) => {
                            matches!(
                                r.execution_result,
                                starknet::core::types::ExecutionResult::Succeeded
                            )
                        }
                        TransactionReceipt::L1Handler(r) => {
                            matches!(
                                r.execution_result,
                                starknet::core::types::ExecutionResult::Succeeded
                            )
                        }
                    };

                    if is_accepted {
                        info!("✅ Transaction confirmed");
                        return Ok(receipt);
                    } else {
                        error!("❌ Transaction reverted");
                        return Err("Transaction reverted".into());
                    }
                }
                Err(_) if attempts < max_attempts => {
                    sleep(Duration::from_secs(5)).await;
                    continue;
                }
                Err(e) => {
                    warn!("⚠️ Transaction not found after {} attempts", attempts);
                    return Err(format!("Transaction lookup failed: {}", e).into());
                }
            }
        }
    }
}
