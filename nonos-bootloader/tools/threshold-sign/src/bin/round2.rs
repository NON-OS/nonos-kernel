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
use nonos_threshold_sign::{round2_sign, KeyShare, SigningNonces, SigningPackage};
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "threshold-round2", about = "FROST round 2: generate signature share")]
struct Args {
    /// Path to signing package (message + all commitments)
    #[arg(short = 'p', long)]
    signing_package: PathBuf,

    /// Path to this participant's nonces (from round 1)
    #[arg(short = 'n', long)]
    nonces: PathBuf,

    /// Path to this participant's key share
    #[arg(short = 'k', long)]
    key_share: PathBuf,

    /// Output path for signature share
    #[arg(short = 'o', long)]
    output: PathBuf,
}

fn main() -> Result<(), String> {
    let args = Args::parse();

    let package_json = fs::read_to_string(&args.signing_package)
        .map_err(|e| format!("failed to read signing package: {}", e))?;
    let signing_package: SigningPackage = serde_json::from_str(&package_json)
        .map_err(|e| format!("failed to parse signing package: {}", e))?;

    let nonces_json = fs::read_to_string(&args.nonces)
        .map_err(|e| format!("failed to read nonces: {}", e))?;
    let nonces: SigningNonces = serde_json::from_str(&nonces_json)
        .map_err(|e| format!("failed to parse nonces: {}", e))?;

    let share_json = fs::read_to_string(&args.key_share)
        .map_err(|e| format!("failed to read key share: {}", e))?;
    let key_share: KeyShare = serde_json::from_str(&share_json)
        .map_err(|e| format!("failed to parse key share: {}", e))?;

    if nonces.participant_id != key_share.participant_id {
        return Err(format!(
            "nonces participant {} does not match key share participant {}",
            nonces.participant_id, key_share.participant_id
        ));
    }

    eprintln!("participant {}: generating signature share", key_share.participant_id);
    eprintln!("  message: {} bytes", signing_package.message.len());
    eprintln!("  commitments from {} participants", signing_package.commitments.len());

    let signature_share = round2_sign(&signing_package, &nonces, &key_share)
        .map_err(|e| format!("signing failed: {}", e))?;

    let share_json = serde_json::to_string_pretty(&signature_share)
        .map_err(|e| format!("failed to serialize signature share: {}", e))?;
    fs::write(&args.output, &share_json)
        .map_err(|e| format!("failed to write signature share: {}", e))?;

    eprintln!("  wrote signature share to {}", args.output.display());
    eprintln!();
    eprintln!("send {} to the coordinator for aggregation", args.output.display());

    // Nonces are consumed - remind user to delete
    eprintln!();
    eprintln!("IMPORTANT: delete {} - nonces must not be reused", args.nonces.display());

    Ok(())
}
