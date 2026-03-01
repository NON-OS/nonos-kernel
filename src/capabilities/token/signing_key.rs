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

use spin::Once;

static SIGNING_KEY: Once<[u8; 32]> = Once::new();

pub fn set_signing_key(key: &[u8]) -> Result<(), &'static str> {
    if key.len() != 32 {
        return Err("Key must be 32 bytes");
    }
    if SIGNING_KEY.get().is_some() {
        return Err("Key already set");
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(key);
    SIGNING_KEY.call_once(|| arr);
    Ok(())
}

#[inline]
pub fn has_signing_key() -> bool {
    SIGNING_KEY.get().is_some()
}

#[inline]
pub fn signing_key() -> Option<&'static [u8; 32]> {
    SIGNING_KEY.get()
}
