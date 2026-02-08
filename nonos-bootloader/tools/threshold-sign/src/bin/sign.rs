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
    aggregate_signatures, round1_commit, round2_sign, verify_signature, KeyShare,
    PublicKeyPackage, SigningPackage,
};
use rand_core::OsRng;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "threshold-sign", about = "FROST threshold signing coordinator")]
struct Args {
    #[arg(short = 'm', long)]
    message: PathBuf,

    #[arg(short = 'k', long, num_args = 1..)]
    key_shares: Vec<PathBuf>,

    #[arg(short = 'p', long)]
    public_key: PathBuf,

    #[arg(short = 'o', long)]
    output: PathBuf,
}

fn main() -> Result<(), String> {
    let args = Args::parse();

    println!("=== NONOS FROST Threshold Signing ===");
    println!();

    let message = fs::read(&args.message)
        .map_err(|e| format!("failed to read message: {}", e))?;
    println!("message: {} bytes", message.len());

    let pubkey_json = fs::read_to_string(&args.public_key)
        .map_err(|e| format!("failed to read public key: {}", e))?;
    let pubkey_package: PublicKeyPackage = serde_json::from_str(&pubkey_json)
        .map_err(|e| format!("failed to parse public key: {}", e))?;

    println!(
        "group public key: {}",
        hex::encode(&pubkey_package.group_public_key)
    );
    println!(
        "threshold: {}-of-{}",
        pubkey_package.config.threshold, pubkey_package.config.total_signers
    );

    if args.key_shares.len() < pubkey_package.config.threshold as usize {
        return Err(format!(
            "insufficient key shares: {} provided, {} required",
            args.key_shares.len(),
            pubkey_package.config.threshold
        ));
    }

    let mut key_shares = Vec::new();
    for path in &args.key_shares {
        let share_json = fs::read_to_string(path)
            .map_err(|e| format!("failed to read key share {}: {}", path.display(), e))?;
        let share: KeyShare = serde_json::from_str(&share_json)
            .map_err(|e| format!("failed to parse key share: {}", e))?;
        println!("  loaded key share {}", share.participant_id);
        key_shares.push(share);
    }
    println!();

    println!("round 1: generating commitments...");
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();

    for share in &key_shares {
        let (nonce, commit) = round1_commit(share, &mut OsRng);
        println!(
            "  participant {}: commitment generated",
            share.participant_id
        );
        nonces.insert(share.participant_id, nonce);
        commitments.insert(share.participant_id, commit);
    }
    println!();

    let signing_package = SigningPackage {
        message: message.clone(),
        commitments: commitments.clone(),
    };

    println!("round 2: generating signature shares...");
    let mut signature_shares = BTreeMap::new();

    for share in &key_shares {
        let nonce = nonces
            .get(&share.participant_id)
            .ok_or("missing nonce")?;
        let sig_share = round2_sign(&signing_package, nonce, share)
            .map_err(|e| format!("signing failed for {}: {}", share.participant_id, e))?;
        println!(
            "  participant {}: signature share generated",
            share.participant_id
        );
        signature_shares.insert(share.participant_id, sig_share);
    }
    println!();

    println!("aggregating signature shares...");
    let signature = aggregate_signatures(&signing_package, &signature_shares, &pubkey_package)
        .map_err(|e| format!("aggregation failed: {}", e))?;

    println!("  signature: {}", hex::encode(&signature));
    println!();

    println!("verifying signature...");
    verify_signature(&message, &signature, &pubkey_package.group_public_key)
        .map_err(|e| format!("verification failed: {}", e))?;
    println!("  signature valid");
    println!();

    fs::write(&args.output, &signature)
        .map_err(|e| format!("failed to write signature: {}", e))?;
    println!("wrote signature to {}", args.output.display());

    println!();
    println!("=== Signing Complete ===");

    Ok(())
}
