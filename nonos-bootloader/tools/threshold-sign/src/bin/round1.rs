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
use nonos_threshold_sign::{round1_commit, KeyShare};
use rand_core::OsRng;
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "threshold-round1", about = "FROST round 1: generate signing commitment")]
struct Args {
    /// Path to this participant's key share
    #[arg(short = 'k', long)]
    key_share: PathBuf,

    /// Output path for commitment (share with coordinator)
    #[arg(short = 'c', long)]
    commitment_out: PathBuf,

    /// Output path for nonces (keep secret, needed for round 2)
    #[arg(short = 'n', long)]
    nonces_out: PathBuf,
}

fn main() -> Result<(), String> {
    let args = Args::parse();

    let share_json = fs::read_to_string(&args.key_share)
        .map_err(|e| format!("failed to read key share: {}", e))?;
    let key_share: KeyShare = serde_json::from_str(&share_json)
        .map_err(|e| format!("failed to parse key share: {}", e))?;

    eprintln!("participant {}: generating round 1 commitment", key_share.participant_id);

    let (nonces, commitment) = round1_commit(&key_share, &mut OsRng);

    // Write commitment (public, share with others)
    let commitment_json = serde_json::to_string_pretty(&commitment)
        .map_err(|e| format!("failed to serialize commitment: {}", e))?;
    fs::write(&args.commitment_out, &commitment_json)
        .map_err(|e| format!("failed to write commitment: {}", e))?;
    eprintln!("  wrote commitment to {}", args.commitment_out.display());

    // Write nonces (secret, keep local for round 2)
    let nonces_json = serde_json::to_string_pretty(&nonces)
        .map_err(|e| format!("failed to serialize nonces: {}", e))?;
    fs::write(&args.nonces_out, &nonces_json)
        .map_err(|e| format!("failed to write nonces: {}", e))?;
    eprintln!("  wrote nonces to {} (KEEP SECRET)", args.nonces_out.display());

    eprintln!();
    eprintln!("send {} to the coordinator", args.commitment_out.display());
    eprintln!("keep {} secret for round 2", args.nonces_out.display());

    Ok(())
}
