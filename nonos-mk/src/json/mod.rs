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

//! JSON-side representation of `abi/marketplace_index.schema.json`.
//! The CLI parses host-friendly JSON, projects it onto the
//! marketplace_abi types, and encodes through the canonical binary
//! path. The JSON form is what publishers and operators edit by
//! hand; the binary form is what the OS verifies.

mod decode_entry;
mod decode_enums;
mod decode_index;
mod decode_release;
mod encode_entry;
mod encode_index;
mod encode_price;
mod encode_release;
mod encode_token;
mod encode_validation;
mod hex_helpers;
mod read;
mod schema;

pub use decode_index::from_index;
pub use encode_index::to_index;
pub(crate) use encode_release::to_release;
pub use read::read_index_json;
