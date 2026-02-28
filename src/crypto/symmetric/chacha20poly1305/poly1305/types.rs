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

pub(crate) struct Poly1305 {
    pub(super) h0: u32,
    pub(super) h1: u32,
    pub(super) h2: u32,
    pub(super) h3: u32,
    pub(super) h4: u32,
    pub(super) r0: u32,
    pub(super) r1: u32,
    pub(super) r2: u32,
    pub(super) r3: u32,
    pub(super) r4: u32,
    pub(super) s1: u32,
    pub(super) s2: u32,
    pub(super) s3: u32,
    pub(super) s4: u32,
    pub(super) s: [u8; 16],
    pub(super) buffer: [u8; 16],
    pub(super) buffer_len: usize,
}
