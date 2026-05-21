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

use spin::Mutex;

static AUTHORITY: Mutex<Option<[u8; 32]>> = Mutex::new(None);

pub fn install(body: &[u8]) -> bool {
    if body.len() != 32 || body.iter().all(|b| *b == 0) {
        return false;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(body);
    *AUTHORITY.lock() = Some(key);
    true
}

pub fn trusted(issuer: &[u8]) -> Option<bool> {
    let guard = AUTHORITY.lock();
    guard.as_ref().map(|key| same(key, issuer))
}

fn same(a: &[u8; 32], b: &[u8]) -> bool {
    if b.len() != 32 {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}
