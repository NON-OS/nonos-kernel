// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use std::fs;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::Parser;

const ZK_PROOF_MAGIC: [u8; 4] = [0x4E, 0xC3, 0x5A, 0x50];

const ZK_PROOF_VERSION: u32 = 1;

const GROTH16_PROOF_SIZE: usize = 192;

const DS_PROGRAM_HASH: &str = "NONOS:ZK:PROGRAM:v1";

#[derive(Parser, Debug)]
#[command(name = "embed-zk-proof", about = "Embed Groth16 ZK proof into signed NONOS kernel")]
struct Args {
    #[arg(short, long, value_name = "FILE")]
    input: PathBuf,

    #[arg(short, long, value_name = "FILE")]
    output: PathBuf,

    #[arg(short = 'p', long, value_name = "FILE")]
    proof: PathBuf,

    #[arg(long, value_name = "STRING", conflicts_with = "program_hash")]
    program_id: Option<String>,

    #[arg(long, value_name = "HEX")]
    program_hash: Option<String>,

    #[arg(long, value_name = "FILE")]
    public_inputs: Option<PathBuf>,

    #[arg(short, long, action = clap::ArgAction::SetTrue)]
    verbose: bool,
}

fn derive_program_hash(program_id: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(DS_PROGRAM_HASH);
    hasher.update(program_id.as_bytes());
    *hasher.finalize().as_bytes()
}

const DS_COMMITMENT: &str = "NONOS:CAPSULE:COMMITMENT:v1";

fn compute_capsule_commitment(public_inputs: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new_derive_key(DS_COMMITMENT);
    hasher.update(public_inputs);
    *hasher.finalize().as_bytes()
}

fn create_zk_proof_block(
    program_hash: &[u8; 32],
    capsule_commitment: &[u8; 32],
    public_inputs: &[u8],
    proof_blob: &[u8],
) -> Result<Vec<u8>> {
    if proof_blob.len() != GROTH16_PROOF_SIZE {
        bail!(
            "Proof blob must be {} bytes, got {}",
            GROTH16_PROOF_SIZE,
            proof_blob.len()
        );
    }
    if public_inputs.len() % 32 != 0 {
        bail!(
            "Public inputs must be 32-byte aligned, got {} bytes",
            public_inputs.len()
        );
    }

    let header_size = 80;
    let total_size = header_size + public_inputs.len() + proof_blob.len();
    let mut block = Vec::with_capacity(total_size);

    block.extend_from_slice(&ZK_PROOF_MAGIC);
    block.extend_from_slice(&ZK_PROOF_VERSION.to_le_bytes());
    block.extend_from_slice(program_hash);
    block.extend_from_slice(capsule_commitment);
    block.extend_from_slice(&(public_inputs.len() as u32).to_le_bytes());
    block.extend_from_slice(&(proof_blob.len() as u32).to_le_bytes());
    block.extend_from_slice(public_inputs);
    block.extend_from_slice(proof_blob);

    Ok(block)
}

fn main() -> Result<()> {
    let args = Args::parse();

    println!("=== NONOS ZK Proof Embedding Tool ===");
    println!();

    let signed_kernel = fs::read(&args.input)
        .with_context(|| format!("Failed to read signed kernel: {}", args.input.display()))?;

    if signed_kernel.len() < 128 {
        bail!("Signed kernel too small (must be at least 128 bytes)");
    }

    println!("Signed kernel size: {} bytes", signed_kernel.len());
    println!("  (includes 64-byte Ed25519 signature)");
    println!();

    let proof_blob = fs::read(&args.proof)
        .with_context(|| format!("Failed to read proof file: {}", args.proof.display()))?;

    if proof_blob.len() != GROTH16_PROOF_SIZE {
        bail!(
            "Proof file must be exactly {} bytes (Groth16 compressed), got {}",
            GROTH16_PROOF_SIZE,
            proof_blob.len()
        );
    }

    println!("Proof file size: {} bytes", proof_blob.len());
    println!();

    let public_inputs = if let Some(ref path) = args.public_inputs {
        let inputs = fs::read(path)
            .with_context(|| format!("Failed to read public inputs: {}", path.display()))?;
        if inputs.len() % 32 != 0 {
            bail!(
                "Public inputs file must be 32-byte aligned, got {} bytes",
                inputs.len()
            );
        }
        println!("Public inputs: {} bytes ({} field elements)", inputs.len(), inputs.len() / 32);
        inputs
    } else {
        println!("Public inputs: none (using default empty)");
        Vec::new()
    };
    println!();

    let program_hash: [u8; 32] = if let Some(ref hex_str) = args.program_hash {
        let bytes = hex::decode(hex_str)
            .with_context(|| "Invalid hex string for program-hash")?;
        if bytes.len() != 32 {
            bail!("program-hash must be 32 bytes (64 hex chars), got {} bytes", bytes.len());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        println!("Program Hash: {} (provided)", hex::encode(&arr));
        arr
    } else if let Some(ref program_id) = args.program_id {
        let hash = derive_program_hash(program_id);
        println!("Program ID: {}", program_id);
        println!("Program Hash: {} (derived)", hex::encode(&hash));
        hash
    } else {
        bail!("Either --program-id or --program-hash must be provided");
    };
    println!();

    let capsule_commitment = compute_capsule_commitment(&public_inputs);
    println!("Capsule Commitment: {}", hex::encode(&capsule_commitment));
    println!();

    let zk_block = create_zk_proof_block(
        &program_hash,
        &capsule_commitment,
        &public_inputs,
        &proof_blob,
    )?;

    println!("ZK Proof Block size: {} bytes", zk_block.len());

    if args.verbose {
        println!();
        println!("=== ZK Block Header ===");
        println!("  Magic:             {:02X?}", &zk_block[0..4]);
        println!("  Version:           {}", u32::from_le_bytes([zk_block[4], zk_block[5], zk_block[6], zk_block[7]]));
        println!("  Program Hash:      {}...", hex::encode(&zk_block[8..16]));
        println!("  Commitment:        {}...", hex::encode(&zk_block[40..48]));
        println!("  Public Inputs Len: {}", u32::from_le_bytes([zk_block[72], zk_block[73], zk_block[74], zk_block[75]]));
        println!("  Proof Blob Len:    {}", u32::from_le_bytes([zk_block[76], zk_block[77], zk_block[78], zk_block[79]]));
    }
    println!();

    let mut output_data = signed_kernel.clone();
    output_data.extend_from_slice(&zk_block);

    fs::write(&args.output, &output_data)
        .with_context(|| format!("Failed to write output: {}", args.output.display()))?;

    println!("=== Output ===");
    println!("Written: {} ({} bytes)", args.output.display(), output_data.len());
    println!();
    println!("Breakdown:");
    println!("  Original kernel:    {} bytes", signed_kernel.len() - 64);
    println!("  Ed25519 signature:  64 bytes");
    println!("  ZK proof block:     {} bytes", zk_block.len());
    println!("  Total:              {} bytes", output_data.len());
    println!();
    println!("The bootloader will now verify both:");
    println!("  1. Ed25519 signature (kernel integrity)");
    println!("  2. Groth16 ZK proof  (boot attestation)");
    println!();

    let magic_offset = output_data.len() - zk_block.len();
    if &output_data[magic_offset..magic_offset + 4] == &ZK_PROOF_MAGIC {
        println!("Verification: ZK magic found at offset 0x{:X}", magic_offset);
    } else {
        println!("WARNING: ZK magic not found at expected offset!");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_program_hash_derivation() {
        let hash1 = derive_program_hash("nonos-boot-attest-v1");
        let hash2 = derive_program_hash("nonos-boot-attest-v1");
        let hash3 = derive_program_hash("nonos-boot-attest-v2");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_zk_block_creation() {
        let program_hash = [0xAAu8; 32];
        let commitment = [0xBBu8; 32];
        let public_inputs = vec![0u8; 64];
        let proof = vec![0u8; 192];

        let block = create_zk_proof_block(&program_hash, &commitment, &public_inputs, &proof).unwrap();

        assert_eq!(&block[0..4], &ZK_PROOF_MAGIC);
        assert_eq!(block.len(), 80 + 64 + 192);
    }
}
