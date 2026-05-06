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

extern crate alloc;

use ed25519_dalek::VerifyingKey;
use nonos_marketplace_abi::MarketplaceIndex;

use super::key::signing_key;

pub fn empty_index() -> MarketplaceIndex {
    let pubkey = VerifyingKey::from(&signing_key()).to_bytes();
    MarketplaceIndex {
        schema_version: 1,
        operator_id: alloc_string("test.operator"),
        operator_pubkey: pubkey,
        published_at_ms: 1_700_000_000_000,
        serial: 1,
        entries: alloc::vec::Vec::new(),
        index_signature: alloc::vec::Vec::new(),
    }
}

fn alloc_string(s: &str) -> alloc::string::String {
    alloc::string::String::from(s)
}
