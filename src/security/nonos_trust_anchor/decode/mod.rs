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

mod header;
mod keys;
mod revocation;

use super::cursor::Cursor;
use super::error::TrustAnchorDecodeError;
use super::schema::{NonosTrustAnchorPolicy, TRUST_ANCHOR_SCHEMA_VERSION};

pub fn decode(bytes: &[u8]) -> Result<NonosTrustAnchorPolicy, TrustAnchorDecodeError> {
    let mut c = Cursor::new(bytes);
    let trust_anchor_epoch = header::decode(&mut c)?;
    let keys_vec = keys::decode(&mut c)?;
    let rev = revocation::decode(&mut c)?;
    let flags = c.u32_be()?;
    if c.pos != bytes.len() {
        return Err(TrustAnchorDecodeError::TrailingBytes);
    }
    Ok(NonosTrustAnchorPolicy {
        schema_version: TRUST_ANCHOR_SCHEMA_VERSION,
        trust_anchor_epoch,
        keys: keys_vec,
        revoked_cert_serials: rev.revoked_cert_serials,
        revoked_nonos_ids: rev.revoked_nonos_ids,
        revoked_publisher_key_ids: rev.revoked_publisher_key_ids,
        flags,
    })
}
