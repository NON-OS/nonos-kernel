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

// Table symbol from vectors.S. 2KB-aligned by construction.
extern "C" {
    static __aarch64_vectors_el1: u8;
}

#[inline]
pub fn vectors_el1_addr() -> u64 {
    // SAFETY: address-of an extern static; never dereferenced here.
    unsafe { &__aarch64_vectors_el1 as *const u8 as u64 }
}
