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
use nonos_threshold_sign::{keygen, ThresholdConfig};
use rand_core::OsRng;
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "threshold-keygen", about = "Generate FROST threshold key shares")]
struct Args {
    #[arg(short = 't', long)]
    threshold: u16,

    #[arg(short = 'n', long)]
    total: u16,

    #[arg(short = 'o', long)]
    output_dir: PathBuf,
}

fn main() -> Result<(), String> {
    let args = Args::parse();

    println!("=== NONOS FROST Threshold Key Generation ===");
    println!();

    if args.threshold == 0 || args.threshold > args.total {
        return Err(format!(
            "invalid threshold: {} must be > 0 and <= {}",
            args.threshold, args.total
        ));
    }

    if args.total < 2 {
        return Err("total participants must be at least 2".into());
    }

    fs::create_dir_all(&args.output_dir)
        .map_err(|e| format!("failed to create output directory: {}", e))?;

    let config = ThresholdConfig::new(args.threshold, args.total)
        .map_err(|e| format!("invalid config: {}", e))?;

    println!(
        "generating {}-of-{} threshold key shares...",
        args.threshold, args.total
    );
    println!();

    let (key_shares, pubkey_package) = keygen(&config, &mut OsRng)
        .map_err(|e| format!("keygen failed: {}", e))?;

    println!(
        "group public key: {}",
        hex::encode(&pubkey_package.group_public_key)
    );
    println!();

    for share in &key_shares {
        let share_path = args
            .output_dir
            .join(format!("key_share_{}.json", share.participant_id));
        let share_json = serde_json::to_string_pretty(share)
            .map_err(|e| format!("failed to serialize share: {}", e))?;
        fs::write(&share_path, share_json)
            .map_err(|e| format!("failed to write share: {}", e))?;
        println!(
            "  wrote key share {} to {}",
            share.participant_id,
            share_path.display()
        );
    }

    let pubkey_path = args.output_dir.join("public_key_package.json");
    let pubkey_json = serde_json::to_string_pretty(&pubkey_package)
        .map_err(|e| format!("failed to serialize public key: {}", e))?;
    fs::write(&pubkey_path, pubkey_json)
        .map_err(|e| format!("failed to write public key: {}", e))?;
    println!();
    println!("  wrote public key package to {}", pubkey_path.display());

    println!();
    println!("=== Key Generation Complete ===");
    println!("distribute key shares securely to each participant");
    println!("the public key package should be shared with all participants");

    Ok(())
}
