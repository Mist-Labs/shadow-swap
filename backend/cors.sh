#!/bin/bash
# Script to patch the crates.io version of starknet-crypto
CRYPTO_PATH="/Users/MAC/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/starknet-crypto-0.8.1/src/pedersen_hash/no_lookup.rs"
echo "Backing up original file..."
cp "$CRYPTO_PATH" "$CRYPTO_PATH.backup"
echo "Applying fix..."
sed -i '' 's/let p0_projective: ProjectivePoint = ProjectivePoint::new(/let p0_projective: ProjectivePoint = ProjectivePoint::new(/g' "$CRYPTO_PATH"
sed -i '' '31s/);/).expect("Failed to create p0_projective");/g' "$CRYPTO_PATH"
sed -i '' '46s/);/).expect("Failed to create p1_projective");/g' "$CRYPTO_PATH"
sed -i '' '61s/);/).expect("Failed to create p2_projective");/g' "$CRYPTO_PATH"
sed -i '' '76s/);/).expect("Failed to create p3_projective");/g' "$CRYPTO_PATH"
echo "Fix applied! Now run: cargo build"