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
//
/// CR4 bit for SMEP (Supervisor Mode Execution Prevention).
pub const CR4_SMEP: u64 = 1 << 20;
/// CR4 bit for SMAP (Supervisor Mode Access Prevention).
pub const CR4_SMAP: u64 = 1 << 21;
/// Required CR4 bits for kernel hardening.
pub const CR4_REQUIRED_BITS: u64 = CR4_SMEP | CR4_SMAP;
/// Pattern used for heap corruption detection.
pub const CORRUPTION_PATTERN: u64 = 0xDEADBEEFCAFEBABE;
/// Canary mixing constant for stack protection.
pub const CANARY_MIX_CONSTANT: u64 = 0x9e3779b97f4a7c15;
/// NOP instruction byte for checking suspicious code.
pub const NOP_INSTRUCTION: u8 = 0x90;
/// Bytes to check for suspicious NOP sleds.
pub const NOP_SLED_CHECK_SIZE: usize = 16;
