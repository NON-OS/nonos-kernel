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

mod baked;
mod cursor;
mod decode;
mod error;
mod schema;

pub use baked::BAKED_TRUST_ANCHOR_POLICY;
pub use decode::decode;
pub use error::TrustAnchorDecodeError;
pub use schema::{
    NonosTrustAnchorPolicy, TrustAnchorKey, MAX_REVOKED_CERT_SERIALS, MAX_REVOKED_NONOS_IDS,
    MAX_REVOKED_PUBLISHER_KEY_IDS, MAX_TRUST_ANCHOR_KEYS, NONOS_ID_LEN, PUBLISHER_KEY_ID_LEN,
    TRUST_ANCHOR_SCHEMA_VERSION,
};
