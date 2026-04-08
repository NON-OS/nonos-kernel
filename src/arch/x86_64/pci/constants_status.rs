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

pub const INTERRUPT_STATUS: u16 = 1 << 3;
pub const CAPABILITIES_LIST: u16 = 1 << 4;
pub const MHZ_66_CAPABLE: u16 = 1 << 5;
pub const FAST_B2B_CAPABLE: u16 = 1 << 7;
pub const MASTER_DATA_PARITY_ERROR: u16 = 1 << 8;
pub const SIGNALED_TARGET_ABORT: u16 = 1 << 11;
pub const RECEIVED_TARGET_ABORT: u16 = 1 << 12;
pub const RECEIVED_MASTER_ABORT: u16 = 1 << 13;
pub const SIGNALED_SYSTEM_ERROR: u16 = 1 << 14;
pub const DETECTED_PARITY_ERROR: u16 = 1 << 15;
