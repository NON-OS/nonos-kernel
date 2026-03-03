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

pub const XHCI_CLASS: u8 = 0x0C;
pub const XHCI_SUBCLASS: u8 = 0x03;
pub const XHCI_PROGIF: u8 = 0x30;

pub const TRB_ALIGNMENT: u64 = 16;
pub const DMA_MIN_ALIGNMENT: usize = 64;
pub const MAX_TRANSFER_SIZE: usize = 1024 * 1024;
pub const MAX_DESCRIPTOR_SIZE: usize = 4096;
pub const MIN_DESCRIPTOR_SIZE: usize = 8;
pub const ENUMERATION_RATE_LIMIT_MS: u64 = 1000;
pub const MAX_ENUMERATION_ATTEMPTS: u32 = 5;
pub const DEFAULT_TIMEOUT_SPINS: u32 = 2_000_000;
pub const MAX_TIMEOUT_SPINS: u32 = 10_000_000;
pub const CONTROLLER_RESET_TIMEOUT: u32 = 1_000_000;
pub const PORT_RESET_TIMEOUT: u32 = 500_000;

pub const DEFAULT_CMD_RING_SIZE: usize = 256;
pub const DEFAULT_EVENT_RING_SIZE: usize = 256;
pub const DEFAULT_TRANSFER_RING_SIZE: usize = 256;
pub const MIN_RING_SIZE: usize = 16;
pub const MAX_RING_SIZE: usize = 4096;
