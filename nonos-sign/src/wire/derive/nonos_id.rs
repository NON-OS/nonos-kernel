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

use crate::error::SignError;
use crate::wire::constants::NONOS_ID_LEN;

const NONOS_ID_DOMAIN: &[u8] = b"nonos.id.v1";

pub fn derive_nonos_id(
    handle: &[u8],
    domain: &[u8],
    recovery: &[u8],
) -> Result<[u8; NONOS_ID_LEN], SignError> {
    check_byte_field("handle", handle.len())?;
    check_byte_field("domain", domain.len())?;
    check_byte_field("recovery", recovery.len())?;
    let mut h = blake3::Hasher::new();
    h.update(NONOS_ID_DOMAIN);
    h.update(&[handle.len() as u8]);
    h.update(handle);
    h.update(&[domain.len() as u8]);
    h.update(domain);
    h.update(&[recovery.len() as u8]);
    h.update(recovery);
    Ok(*h.finalize().as_bytes())
}

fn check_byte_field(name: &'static str, len: usize) -> Result<(), SignError> {
    if len > u8::MAX as usize {
        return Err(SignError::DeriveFieldTooLong { field: name, len });
    }
    Ok(())
}
