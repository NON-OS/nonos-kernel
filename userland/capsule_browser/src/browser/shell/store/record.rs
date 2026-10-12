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

use alloc::vec::Vec;

use super::codec::{encode, Persisted};

/// Every record is written at this one size. The disk store overwrites a
/// kept file in place only with bytes of the same length, so a record that
/// grew by a bookmark would never reach the disk again.
pub const RECORD_BYTES: usize = 32 * 1024;

/// `p` encoded and padded with zeros to `RECORD_BYTES`. When it does not fit,
/// the oldest bookmarks are dropped from `p` until it does, so the window
/// shows only what the disk will keep. The decoder stops at the last section,
/// so the padding reads as nothing.
pub fn fixed(p: &mut Persisted) -> Vec<u8> {
    loop {
        let mut out = encode(p);
        if out.len() <= RECORD_BYTES {
            out.resize(RECORD_BYTES, 0);
            return out;
        }
        if p.bookmarks.is_empty() {
            return out;
        }
        p.bookmarks.remove(0);
    }
}
