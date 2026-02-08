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
use nonos_threshold_sign::{
    aggregate_signatures, verify_signature, PublicKeyPackage, SignatureShare, SigningPackage,
};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "threshold-aggregate", about = "FROST: aggregate signature shares")]
struct Args {
    /// Path to signing package (message + commitments)
    #[arg(short = 'p', long)]
    signing_package: PathBuf,

    /// Paths to signature share files
    #[arg(short = 's', long, num_args = 1..)]
    shares: Vec<PathBuf>,

    /// Path to public key package
    #[arg(short = 'k', long)]
    public_key: PathBuf,

    /// Output path for final signature
    #[arg(short = 'o', long)]
    output: PathBuf,
}

fn main() -> Result<(), String> {
    let args = Args::parse();

    eprintln!("=== FROST Signature Aggregation ===");
    eprintln!();

    let package_json = fs::read_to_string(&args.signing_package)
        .map_err(|e| format!("failed to read signing package: {}", e))?;
    let signing_package: SigningPackage = serde_json::from_str(&package_json)
        .map_err(|e| format!("failed to parse signing package: {}", e))?;

    let pubkey_json = fs::read_to_string(&args.public_key)
        .map_err(|e| format!("failed to read public key: {}", e))?;
    let pubkey_package: PublicKeyPackage = serde_json::from_str(&pubkey_json)
        .map_err(|e| format!("failed to parse public key: {}", e))?;

    eprintln!("threshold: {}-of-{}", pubkey_package.config.threshold, pubkey_package.config.total_signers);
    eprintln!("message: {} bytes", signing_package.message.len());
    eprintln!();

    if args.shares.len() < pubkey_package.config.threshold as usize {
        return Err(format!(
            "insufficient shares: {} provided, {} required",
            args.shares.len(),
            pubkey_package.config.threshold
        ));
    }

    let mut signature_shares = BTreeMap::new();
    for path in &args.shares {
        let share_json = fs::read_to_string(path)
            .map_err(|e| format!("failed to read {}: {}", path.display(), e))?;
        let share: SignatureShare = serde_json::from_str(&share_json)
            .map_err(|e| format!("failed to parse {}: {}", path.display(), e))?;
        eprintln!("  loaded share from participant {}", share.participant_id);
        signature_shares.insert(share.participant_id, share);
    }
    eprintln!();

    eprintln!("aggregating {} signature shares...", signature_shares.len());
    let signature = aggregate_signatures(&signing_package, &signature_shares, &pubkey_package)
        .map_err(|e| format!("aggregation failed: {}", e))?;

    eprintln!("  signature: {}", hex::encode(&signature));
    eprintln!();

    eprintln!("verifying aggregated signature...");
    verify_signature(&signing_package.message, &signature, &pubkey_package.group_public_key)
        .map_err(|e| format!("verification failed: {}", e))?;
    eprintln!("  verification: PASSED");
    eprintln!();

    fs::write(&args.output, &signature)
        .map_err(|e| format!("failed to write signature: {}", e))?;
    eprintln!("wrote 64-byte signature to {}", args.output.display());

    Ok(())
}
