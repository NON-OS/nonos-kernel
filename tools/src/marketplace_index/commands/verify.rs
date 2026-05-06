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

//! `verify` decodes a signed blob, checks the signature against a
//! supplied trust pubkey, and optionally enforces a strict
//! monotonic-serial rule. Failure modes map to distinct exit codes
//! so a CI step can tell a malformed blob from a refused signature
//! from a serial rollback.

use std::path::Path;

use nonos_marketplace_abi::decode_index;

use crate::args::Flags;
use crate::error::CliError;
use crate::keys::{parse_pubkey, verify_signature};

pub fn run(flags: &Flags) -> Result<(), CliError> {
    let in_path = flags.require("in").map_err(CliError::Json)?;
    let pubkey_hex = flags.require("pubkey").map_err(CliError::Json)?;

    let trust_pubkey = parse_pubkey(pubkey_hex)?;
    let blob = std::fs::read(in_path)?;
    let decoded = decode_index(&blob).map_err(|e| CliError::DecodeFailed(format!("{e:?}")))?;

    if decoded.index.operator_pubkey != trust_pubkey {
        return Err(CliError::OperatorPubkeyMismatch);
    }

    let signature: [u8; 64] = decoded
        .index
        .index_signature
        .as_slice()
        .try_into()
        .map_err(|_| {
            CliError::DecodeFailed(format!(
                "index_signature: expected 64 bytes, got {}",
                decoded.index.index_signature.len()
            ))
        })?;
    if !verify_signature(&trust_pubkey, decoded.signed_bytes, &signature) {
        return Err(CliError::SignatureRefused);
    }

    super::serial_guard::enforce_monotonic(decoded.index.serial, flags)?;

    eprintln!(
        "verified: {} (serial {}, {} entries)",
        Path::new(in_path).display(),
        decoded.index.serial,
        decoded.index.entries.len()
    );
    Ok(())
}
