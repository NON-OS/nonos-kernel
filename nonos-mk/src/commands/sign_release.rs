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

//! Attach a publisher signature to one release in the editable JSON
//! index. Operator signing remains a separate command; this keeps
//! publisher authority and marketplace-operator authority distinct.

use std::path::Path;

use nonos_marketplace_abi::release_signing_bytes;

use crate::args::Flags;
use crate::error::CliError;
use crate::json::{read_index_json, to_release};
use crate::keys::parse_pubkey;

use super::load_key::load_operator_key;

pub fn run(flags: &Flags) -> Result<(), CliError> {
    let in_path = flags.require("in").map_err(CliError::Json)?;
    let out_path = flags.require("out").map_err(CliError::Json)?;
    let listing_id = flags.require("listing-id").map_err(CliError::Json)?;
    let release_id = flags.require("release-id").map_err(CliError::Json)?;

    let key = load_operator_key(flags)?;
    let pubkey = key.pubkey_bytes();
    let mut json = read_index_json(Path::new(in_path))?;

    let entry = json
        .entries
        .iter_mut()
        .find(|e| e.listing_id == listing_id)
        .ok_or_else(|| CliError::Json(format!("listing not found: {listing_id}")))?;
    if parse_pubkey(&entry.publisher_pubkey)? != pubkey {
        return Err(CliError::PublisherPubkeyMismatch);
    }

    let release = entry
        .releases
        .iter_mut()
        .find(|r| r.release_id == release_id)
        .ok_or_else(|| CliError::Json(format!("release not found: {release_id}")))?;
    release.publisher_signature.clear();
    let canonical = to_release(release)?;
    let signature = key.sign(&release_signing_bytes(&canonical));
    release.publisher_signature = hex::encode(signature);

    let pretty = serde_json::to_string_pretty(&json).map_err(|e| CliError::Json(e.to_string()))?;
    std::fs::write(out_path, pretty)?;
    eprintln!("wrote publisher-signed json: {out_path}");
    println!("publisher_pubkey {}", hex::encode(pubkey));
    Ok(())
}
