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

//! Top-level JSON → MarketplaceIndex projection. The signature
//! field is left empty here; callers fill it in after signing the
//! canonical bytes returned by the encoder.

use nonos_marketplace_abi::MarketplaceIndex;

use crate::error::CliError;

use super::encode_entry::to_entry;
use super::schema::IndexJson;

pub fn to_index(json: &IndexJson, operator_pubkey: [u8; 32]) -> Result<MarketplaceIndex, CliError> {
    let mut entries = Vec::with_capacity(json.entries.len());
    for entry in &json.entries {
        entries.push(to_entry(entry)?);
    }
    Ok(MarketplaceIndex {
        schema_version: json.schema_version,
        operator_id: json.operator_id.clone(),
        operator_pubkey,
        published_at_ms: json.published_at_ms,
        serial: json.serial,
        entries,
        index_signature: Vec::new(),
    })
}
