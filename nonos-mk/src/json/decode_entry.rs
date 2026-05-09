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

use nonos_marketplace_abi::MarketplaceEntry;

use super::decode_enums::price_kind_str;
use super::decode_release::release_to_json;
use super::schema::{EntryJson, PriceJson, TokenJson};

pub(super) fn entry_to_json(e: &MarketplaceEntry) -> EntryJson {
    EntryJson {
        listing_id: e.listing_id.clone(),
        capsule_id: hex::encode(e.capsule_id),
        name: e.name.clone(),
        publisher_name: e.publisher_name.clone(),
        publisher_pubkey: hex::encode(e.publisher_pubkey),
        description: e.description.clone(),
        price: PriceJson {
            kind: price_kind_str(e.price.kind).to_string(),
            amount_atomic: e.price.amount_atomic.to_string(),
            period_seconds: e.price.period_seconds,
        },
        token: TokenJson {
            symbol: e.token.symbol.clone(),
            decimals: e.token.decimals,
            chain_id: e.token.chain_id,
            contract_address: if e.token.contract_address.is_empty() {
                String::new()
            } else {
                format!("0x{}", hex::encode(&e.token.contract_address))
            },
        },
        releases: e.releases.iter().map(release_to_json).collect(),
    }
}
