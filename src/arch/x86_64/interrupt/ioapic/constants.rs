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

pub(crate) const IOREGSEL: u64 = 0x00;
pub(crate) const IOWIN: u64 = 0x10;
pub(crate) const IOAPICVER: u32 = 0x01;
pub(crate) const IOREDTBL0: u32 = 0x10;

pub(crate) const MAX_IOAPIC: usize = 8;
pub(crate) const MAX_GSI: usize = 1024;
pub(crate) const VEC_MIN: u8 = 0x30;
pub(crate) const VEC_MAX: u8 = 0x7E;
