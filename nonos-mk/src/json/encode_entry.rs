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

use crate::error::CliError;

use super::encode_price::to_price;
use super::encode_release::to_release;
use super::encode_token::to_token;
use super::hex_helpers::hex32;
use super::schema::EntryJson;

pub(super) fn to_entry(e: &EntryJson) -> Result<MarketplaceEntry, CliError> {
    Ok(MarketplaceEntry {
        listing_id: e.listing_id.clone(),
        capsule_id: hex32(&e.capsule_id, "capsule_id")?,
        name: e.name.clone(),
        publisher_name: e.publisher_name.clone(),
        publisher_pubkey: hex32(&e.publisher_pubkey, "publisher_pubkey")?,
        description: e.description.clone(),
        price: to_price(&e.price)?,
        token: to_token(&e.token)?,
        releases: e
            .releases
            .iter()
            .map(to_release)
            .collect::<Result<_, _>>()?,
    })
}
