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

//! `sign` produces the canonical signed blob. Operator key is held
//! in memory only for the duration of the call. Output is
//! deterministic for a given (input, key, serial) triple — the
//! encoder is structural and Ed25519 is deterministic.

use std::path::Path;

use crate::args::Flags;
use crate::encoder::sign_index;
use crate::error::CliError;
use crate::json::{from_index, read_index_json, to_index};
use crate::keys::parse_pubkey;

use super::load_key::load_operator_key;
use super::serial_guard::enforce_monotonic;

pub fn run(flags: &Flags) -> Result<(), CliError> {
    let in_path = flags.require("in").map_err(CliError::Json)?;
    let out_path = flags.require("out").map_err(CliError::Json)?;

    let key = load_operator_key(flags)?;
    let pubkey = key.pubkey_bytes();

    if let Some(expected) = flags.optional("pubkey") {
        if parse_pubkey(expected)? != pubkey {
            return Err(CliError::OperatorPubkeyMismatch);
        }
    }

    let json = read_index_json(Path::new(in_path))?;
    enforce_monotonic(json.serial, flags)?;

    let serial = json.serial;
    let index = to_index(&json, pubkey)?;

    if let Some(json_out) = flags.optional("json-out") {
        let normalized = from_index(&index);
        let pretty = serde_json::to_string_pretty(&normalized)
            .map_err(|e| CliError::Json(e.to_string()))?;
        std::fs::write(json_out, pretty)?;
    }

    let blob = sign_index(index, &key);
    std::fs::write(out_path, &blob)?;

    eprintln!("wrote signed blob: {out_path} ({} bytes, serial {serial})", blob.len());
    println!("operator_pubkey {}", hex::encode(pubkey));
    Ok(())
}
