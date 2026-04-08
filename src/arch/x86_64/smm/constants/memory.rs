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

pub const LEGACY_SMRAM_BASE: u64 = 0xA0000;
pub const LEGACY_SMRAM_SIZE: u64 = 0x20000;
pub const SMM_ENTRY_OFFSET: u64 = 0x8000;
pub const SMM_SAVE_STATE_32: u64 = 0xFE00;
pub const SMM_SAVE_STATE_64: u64 = 0xFC00;
