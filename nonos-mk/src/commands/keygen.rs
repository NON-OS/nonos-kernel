// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
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

//! `keygen` writes a fresh 32-byte Ed25519 seed to disk with mode
//! 0600 and prints only the matching pubkey. The seed file is
//! never overwritten silently — the caller must remove the prior
//! file first. Existing seeds are not exfiltrated.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand::RngCore;

use crate::args::Flags;
use crate::error::CliError;

pub fn run(flags: &Flags) -> Result<(), CliError> {
    let out_path = flags.require("out").map_err(CliError::Json)?;
    let path = Path::new(out_path);
    if path.exists() {
        return Err(CliError::KeyError(format!("refusing to overwrite {out_path}")));
    }

    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let signing = SigningKey::from_bytes(&seed);
    let pubkey = signing.verifying_key().to_bytes();

    let mut file = open_secret(path)?;
    file.write_all(&seed)?;
    file.sync_all()?;

    eprintln!("wrote operator seed: {out_path}");
    println!("operator_pubkey {}", hex::encode(pubkey));
    Ok(())
}

#[cfg(unix)]
fn open_secret(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn open_secret(path: &Path) -> std::io::Result<std::fs::File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}
