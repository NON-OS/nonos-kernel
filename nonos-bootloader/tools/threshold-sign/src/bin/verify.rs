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

use clap::Parser;
use nonos_threshold_sign::{verify_signature, PublicKeyPackage};
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "threshold-verify", about = "Verify a FROST threshold signature")]
struct Args {
    /// Path to message file
    #[arg(short = 'm', long)]
    message: PathBuf,

    /// Path to signature file (64 bytes)
    #[arg(short = 's', long)]
    signature: PathBuf,

    /// Path to public key package JSON, or raw 32-byte public key
    #[arg(short = 'k', long)]
    public_key: PathBuf,
}

fn main() -> Result<(), String> {
    let args = Args::parse();

    let message = fs::read(&args.message)
        .map_err(|e| format!("failed to read message: {}", e))?;

    let sig_bytes = fs::read(&args.signature)
        .map_err(|e| format!("failed to read signature: {}", e))?;

    if sig_bytes.len() != 64 {
        return Err(format!("signature must be 64 bytes, got {}", sig_bytes.len()));
    }

    let signature: [u8; 64] = sig_bytes.try_into().unwrap();

    // Try to load as JSON first, fall back to raw bytes
    let public_key: [u8; 32] = if let Ok(json) = fs::read_to_string(&args.public_key) {
        if let Ok(pkg) = serde_json::from_str::<PublicKeyPackage>(&json) {
            pkg.group_public_key
        } else {
            // Try as hex string
            let hex_str = json.trim();
            if hex_str.len() == 64 {
                let bytes = hex::decode(hex_str)
                    .map_err(|e| format!("failed to decode hex public key: {}", e))?;
                bytes.try_into().map_err(|_| "invalid public key length")?
            } else {
                return Err("public key file is not valid JSON or hex".into());
            }
        }
    } else {
        // Raw binary
        let bytes = fs::read(&args.public_key)
            .map_err(|e| format!("failed to read public key: {}", e))?;
        if bytes.len() != 32 {
            return Err(format!("public key must be 32 bytes, got {}", bytes.len()));
        }
        bytes.try_into().unwrap()
    };

    eprintln!("message: {} bytes", message.len());
    eprintln!("signature: {}", hex::encode(&signature));
    eprintln!("public key: {}", hex::encode(&public_key));
    eprintln!();

    match verify_signature(&message, &signature, &public_key) {
        Ok(()) => {
            println!("VALID");
            Ok(())
        }
        Err(e) => {
            println!("INVALID: {}", e);
            std::process::exit(1);
        }
    }
}
