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

pub const IPC_PAYLOAD_MAX: usize = 1024;
pub const STATUS_LEN: usize = 4;
pub const MAX_BINDINGS: usize = 8;
pub const CBW_LEN: usize = 31;
pub const CSW_LEN: usize = 13;
pub const BLOCK_BYTES: u32 = 512;
pub const MAX_TRANSFER_BLOCKS: u16 = 128;
