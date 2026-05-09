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

//! `encode` writes an *unsigned* canonical blob. The OS rejects
//! unsigned blobs at install_ready time; this subcommand exists for
//! offline encoder/decoder roundtrip tests and for staging an index
//! that will be signed in a separate, isolated step.

use std::path::Path;

use nonos_marketplace_abi::encode_index;

use crate::args::Flags;
use crate::error::CliError;
use crate::json::{read_index_json, to_index};
use crate::keys::parse_pubkey;

pub fn run(flags: &Flags) -> Result<(), CliError> {
    let in_path = flags.require("in").map_err(CliError::Json)?;
    let out_path = flags.require("out").map_err(CliError::Json)?;
    let pubkey_hex = flags.require("pubkey").map_err(CliError::Json)?;

    let json = read_index_json(Path::new(in_path))?;
    let pubkey = parse_pubkey(pubkey_hex)?;
    let index = to_index(&json, pubkey)?;
    let encoded = encode_index(&index);
    std::fs::write(out_path, &encoded.blob)?;

    eprintln!(
        "wrote unsigned blob: {} ({} bytes, {} entries, serial {})",
        out_path,
        encoded.blob.len(),
        index.entries.len(),
        index.serial
    );
    Ok(())
}
