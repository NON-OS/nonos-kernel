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
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};

mod vault;
use vault::{sign_kernel_with_vault, VaultClient};

#[derive(Parser, Debug)]
#[command(name = "nonos-sign-kernel", about = "Sign NONOS kernel binary with Ed25519")]
struct Args {
    #[arg(short, long, value_name = "FILE", conflicts_with = "vault_addr")]
    key: Option<PathBuf>,

    #[arg(short, long, value_name = "FILE")]
    input: PathBuf,

    #[arg(short, long, value_name = "FILE")]
    output: PathBuf,

    #[arg(long, value_name = "URL")]
    vault_addr: Option<String>,

    #[arg(long, value_name = "TOKEN", env = "VAULT_TOKEN")]
    vault_token: Option<String>,

    #[arg(long, value_name = "NAME", default_value = "nonos-kernel-signing")]
    vault_key_name: String,

    #[arg(long, action = clap::ArgAction::SetTrue)]
    verify: bool,

    #[arg(short, long, action = clap::ArgAction::SetTrue)]
    verbose: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    println!("=== NONOS Kernel Signing Tool ===");
    println!();

    let kernel_data = fs::read(&args.input)
        .with_context(|| format!("Failed to read kernel: {}", args.input.display()))?;

    println!("Kernel size: {} bytes", kernel_data.len());

    let kernel_hash = blake3::hash(&kernel_data);
    println!("Kernel BLAKE3: {}", kernel_hash.to_hex());
    println!();

    let (sig_bytes, verifying_key) = if let Some(ref vault_addr) = args.vault_addr {
        let vault_token = args
            .vault_token
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("VAULT_TOKEN required when using --vault-addr"))?;

        println!("Signing via HashiCorp Vault...");
        println!("  Vault address: {}", vault_addr);
        println!("  Key name: {}", args.vault_key_name);
        println!();

        let client = VaultClient::new(vault_addr.clone(), vault_token.clone(), None)
            .map_err(|e| anyhow::anyhow!("vault connection failed: {}", e))?;

        let pubkey_bytes = client
            .get_transit_public_key(&args.vault_key_name)
            .map_err(|e| anyhow::anyhow!("failed to get public key: {}", e))?;

        let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes)
            .map_err(|e| anyhow::anyhow!("invalid public key: {}", e))?;

        println!("Public Key (hex): {}", hex::encode(verifying_key.as_bytes()));

        let pk_hash = blake3::hash(verifying_key.as_bytes());
        println!("Public Key BLAKE3: {}", pk_hash.to_hex());
        println!();

        let sig_bytes = sign_kernel_with_vault(vault_addr, vault_token, &args.vault_key_name, &kernel_data)
            .map_err(|e| anyhow::anyhow!("vault signing failed: {}", e))?;

        (sig_bytes, verifying_key)
    } else if let Some(ref key_path) = args.key {
        let key_bytes = fs::read(key_path)
            .with_context(|| format!("Failed to read key file: {}", key_path.display()))?;

        if key_bytes.len() != 32 {
            bail!(
                "Key file must be exactly 32 bytes (Ed25519 seed), got {} bytes",
                key_bytes.len()
            );
        }

        let mut seed = [0u8; 32];
        seed.copy_from_slice(&key_bytes);

        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key: VerifyingKey = (&signing_key).into();

        println!("Public Key (hex): {}", hex::encode(verifying_key.as_bytes()));

        let pk_hash = blake3::hash(verifying_key.as_bytes());
        println!("Public Key BLAKE3: {}", pk_hash.to_hex());
        println!();

        println!("Signing kernel with Ed25519 (local key)...");
        let signature = signing_key.sign(&kernel_data);

        (signature.to_bytes(), verifying_key)
    } else {
        bail!("Must provide either --key or --vault-addr");
    };

    println!("Signature (R): {}", hex::encode(&sig_bytes[..32]));
    println!("Signature (S): {}", hex::encode(&sig_bytes[32..]));
    println!();

    let mut output_data = kernel_data.clone();
    output_data.extend_from_slice(&sig_bytes);

    fs::write(&args.output, &output_data)
        .with_context(|| format!("Failed to write output: {}", args.output.display()))?;

    println!(
        "Wrote signed kernel: {} ({} bytes)",
        args.output.display(),
        output_data.len()
    );

    if args.verify {
        println!();
        println!("=== Verification ===");

        let signed_data = fs::read(&args.output)?;
        if signed_data.len() < 64 {
            bail!("Signed file too small");
        }

        let sig_offset = signed_data.len() - 64;
        let payload = &signed_data[..sig_offset];
        let sig_bytes_read = &signed_data[sig_offset..];

        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(sig_bytes_read);
        let sig_read = ed25519_dalek::Signature::from_bytes(&sig_arr);

        use ed25519_dalek::Verifier;
        match verifying_key.verify(payload, &sig_read) {
            Ok(()) => {
                println!("Signature verification: PASSED");
            }
            Err(e) => {
                println!("Signature verification: FAILED - {:?}", e);
                bail!("Verification failed");
            }
        }
    }

    println!();
    println!("=== Summary ===");
    println!("Input:     {}", args.input.display());
    println!("Output:    {}", args.output.display());
    if let Some(ref key_path) = args.key {
        println!("Key:       {}", key_path.display());
    } else if let Some(ref vault_addr) = args.vault_addr {
        println!("Vault:     {} (key: {})", vault_addr, args.vault_key_name);
    }
    println!("Signature: Ed25519 (RFC 8032)");
    println!();
    println!("IMPORTANT: Embed this public key in the bootloader:");
    println!();

    let pk = verifying_key.as_bytes();
    println!("pub const NONOS_SIGNING_KEY: &[u8; 32] = &[");
    for (i, chunk) in pk.chunks(8).enumerate() {
        let hex_line: Vec<String> = chunk.iter().map(|b| format!("0x{:02x}", b)).collect();
        if i < pk.len() / 8 - 1 || pk.len() % 8 != 0 {
            println!("    {},", hex_line.join(", "));
        } else {
            println!("    {},", hex_line.join(", "));
        }
    }
    println!("];");

    Ok(())
}
