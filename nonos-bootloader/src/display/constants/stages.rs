// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

pub const STAGE_INIT: u8 = 0;
pub const STAGE_UEFI: u8 = 1;
pub const STAGE_SECURITY: u8 = 2;
pub const STAGE_HARDWARE: u8 = 3;
pub const STAGE_KERNEL_LOAD: u8 = 4;
pub const STAGE_BLAKE3_HASH: u8 = 5;
pub const STAGE_ED25519_VERIFY: u8 = 6;
pub const STAGE_ZK_VERIFY: u8 = 7;
pub const STAGE_ELF_PARSE: u8 = 8;
pub const STAGE_HANDOFF: u8 = 9;
pub const STAGE_COMPLETE: u8 = 10;
