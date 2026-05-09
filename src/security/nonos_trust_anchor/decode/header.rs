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

use super::super::cursor::Cursor;
use super::super::error::TrustAnchorDecodeError;
use super::super::schema::TRUST_ANCHOR_SCHEMA_VERSION;

pub(super) fn decode(c: &mut Cursor<'_>) -> Result<u64, TrustAnchorDecodeError> {
    if c.u16_be()? != TRUST_ANCHOR_SCHEMA_VERSION {
        return Err(TrustAnchorDecodeError::SchemaVersion);
    }
    c.u64_be()
}
