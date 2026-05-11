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

//! Bit definitions for the 8254x control / status / RCTL / TCTL /
//! EERD registers. Bring-up uses CTRL.RST for the reset, polls
//! STATUS.LU for link, programs RCTL/TCTL to enable the rings,
//! and walks EERD to read the MAC out of the on-chip EEPROM.

// CTRL (0x0000). The capsule clears LRST, sets SLU + ASDE so the
// PHY auto-negotiates speed and duplex, and writes RST during
// reset. Forcing duplex via CTRL.FD is left to a follow-on slice
// — auto-negotiation handles it on every QEMU and physical part
// the capsule currently targets.
pub const CTRL_LRST: u32 = 1 << 3;
pub const CTRL_ASDE: u32 = 1 << 5;
pub const CTRL_SLU: u32 = 1 << 6;
pub const CTRL_RST: u32 = 1 << 26;

// STATUS (0x0008). `link_status` reports the LU bit; duplex
// reporting is not yet on the IPC contract.
pub const STATUS_LU: u32 = 1 << 1;

// RCTL (0x0100)
pub const RCTL_EN: u32 = 1 << 1;
pub const RCTL_BAM: u32 = 1 << 15;
pub const RCTL_BSIZE_2048: u32 = 0;
pub const RCTL_SECRC: u32 = 1 << 26;

// TCTL (0x0400)
pub const TCTL_EN: u32 = 1 << 1;
pub const TCTL_PSP: u32 = 1 << 3;
pub const TCTL_CT_SHIFT: u32 = 4;
pub const TCTL_COLD_SHIFT: u32 = 12;
pub const TCTL_CT_DEFAULT: u32 = 0x10 << TCTL_CT_SHIFT;
pub const TCTL_COLD_FULL_DUPLEX: u32 = 0x40 << TCTL_COLD_SHIFT;

// EERD (0x0014). Setting `START` (bit 0) requests a read at the
// 8-bit address in [15:8]; the device sets `DONE` (bit 4) when
// the 16-bit value is in [31:16]. Some 8254x parts use bit 1 as
// START and bit 4 as DONE (older silicon); the 82540EM/82545EM
// family uses 0/4 — match that here.
pub const EERD_START: u32 = 1 << 0;
pub const EERD_DONE: u32 = 1 << 4;
pub const EERD_ADDR_SHIFT: u32 = 8;
pub const EERD_DATA_SHIFT: u32 = 16;

// RAH bit 31 enables the receive-address register.
pub const RAH_AV: u32 = 1 << 31;
