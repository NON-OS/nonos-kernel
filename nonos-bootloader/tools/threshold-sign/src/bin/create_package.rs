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
use nonos_threshold_sign::{SigningCommitments, SigningPackage};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "threshold-create-package", about = "Create FROST signing package")]
struct Args {
    /// Path to message file to sign
    #[arg(short = 'm', long)]
    message: PathBuf,

    /// Paths to commitment files from participants
    #[arg(short = 'c', long, num_args = 1..)]
    commitments: Vec<PathBuf>,

    /// Output path for signing package
    #[arg(short = 'o', long)]
    output: PathBuf,
}

fn main() -> Result<(), String> {
    let args = Args::parse();

    let message = fs::read(&args.message)
        .map_err(|e| format!("failed to read message: {}", e))?;

    eprintln!("message: {} bytes", message.len());
    eprintln!("loading {} commitments...", args.commitments.len());

    let mut commitments = BTreeMap::new();
    for path in &args.commitments {
        let json = fs::read_to_string(path)
            .map_err(|e| format!("failed to read {}: {}", path.display(), e))?;
        let commit: SigningCommitments = serde_json::from_str(&json)
            .map_err(|e| format!("failed to parse {}: {}", path.display(), e))?;
        eprintln!("  participant {}", commit.participant_id);
        commitments.insert(commit.participant_id, commit);
    }

    let package = SigningPackage {
        message,
        commitments,
    };

    let package_json = serde_json::to_string_pretty(&package)
        .map_err(|e| format!("failed to serialize package: {}", e))?;
    fs::write(&args.output, &package_json)
        .map_err(|e| format!("failed to write package: {}", e))?;

    eprintln!();
    eprintln!("wrote signing package to {}", args.output.display());
    eprintln!("distribute to all participating signers for round 2");

    Ok(())
}
