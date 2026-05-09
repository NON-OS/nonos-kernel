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

use nonos_marketplace_abi::MarketplaceIndex;

use super::decode_entry::entry_to_json;
use super::schema::IndexJson;

pub fn from_index(index: &MarketplaceIndex) -> IndexJson {
    IndexJson {
        schema_version: index.schema_version,
        operator_id: index.operator_id.clone(),
        published_at_ms: index.published_at_ms,
        serial: index.serial,
        entries: index.entries.iter().map(entry_to_json).collect(),
    }
}
