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

//! Serde shape mirrors the field names in
//! `abi/marketplace_index.schema.json`. Hex-encoded fields stay as
//! strings here and are converted at the IR boundary; numeric and
//! enum fields keep the JSON spelling so a hand-edited JSON file is
//! the authority.

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct IndexJson {
    pub schema_version: u32,
    pub operator_id: String,
    pub published_at_ms: u64,
    pub serial: u64,
    pub entries: Vec<EntryJson>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EntryJson {
    pub listing_id: String,
    pub capsule_id: String,
    pub name: String,
    pub publisher_name: String,
    pub publisher_pubkey: String,
    pub description: String,
    pub price: PriceJson,
    pub token: TokenJson,
    pub releases: Vec<ReleaseJson>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PriceJson {
    pub kind: String,
    pub amount_atomic: String,
    pub period_seconds: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenJson {
    pub symbol: String,
    pub decimals: u8,
    pub chain_id: u64,
    #[serde(default)]
    pub contract_address: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReleaseJson {
    pub release_id: String,
    pub manifest_hash: String,
    pub package_hash: String,
    pub package_url: String,
    #[serde(default)]
    pub publisher_signature: String,
    pub supported_arches: Vec<String>,
    pub kernel_abi_min: u32,
    pub required_capabilities: Vec<String>,
    pub validation: ValidationJson,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ValidationJson {
    pub status: String,
    #[serde(default)]
    pub note: String,
    pub validator_id: String,
    pub validated_at_ms: u64,
}
