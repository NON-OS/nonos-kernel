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

pub const MSI_CTRL_ENABLE: u16 = 1 << 0;
pub const MSI_CTRL_MMC_MASK: u16 = 0x7 << 1;
pub const MSI_CTRL_MME_MASK: u16 = 0x7 << 4;
pub const MSI_CTRL_64BIT: u16 = 1 << 7;
pub const MSI_CTRL_PVM: u16 = 1 << 8;
pub const MSI_CTRL_EXT_MSG_DATA: u16 = 1 << 9;
pub const MSI_CTRL_EXT_MSG_DATA_CAP: u16 = 1 << 10;

pub const MSIX_CTRL_ENABLE: u16 = 1 << 15;
pub const MSIX_CTRL_FUNCTION_MASK: u16 = 1 << 14;
pub const MSIX_CTRL_TABLE_SIZE_MASK: u16 = 0x07FF;
pub const MSIX_ENTRY_SIZE: u32 = 16;
pub const MSIX_ENTRY_ADDR_LO: u32 = 0;
pub const MSIX_ENTRY_ADDR_HI: u32 = 4;
pub const MSIX_ENTRY_DATA: u32 = 8;
pub const MSIX_ENTRY_VECTOR_CTRL: u32 = 12;
pub const MSIX_ENTRY_MASKED: u32 = 1 << 0;

pub const PM_CAP_VER_MASK: u16 = 0x7;
pub const PM_CAP_PME_CLOCK: u16 = 1 << 3;
pub const PM_CAP_DSI: u16 = 1 << 5;
pub const PM_CAP_AUX_MASK: u16 = 0x7 << 6;
pub const PM_CAP_D1: u16 = 1 << 9;
pub const PM_CAP_D2: u16 = 1 << 10;
pub const PM_CAP_PME_D0: u16 = 1 << 11;
pub const PM_CAP_PME_D1: u16 = 1 << 12;
pub const PM_CAP_PME_D2: u16 = 1 << 13;
pub const PM_CAP_PME_D3_HOT: u16 = 1 << 14;
pub const PM_CAP_PME_D3_COLD: u16 = 1 << 15;

pub const PM_CTRL_STATE_MASK: u16 = 0x3;
pub const PM_CTRL_NO_SOFT_RESET: u16 = 1 << 3;
pub const PM_CTRL_PME_ENABLE: u16 = 1 << 8;
pub const PM_CTRL_DATA_SEL_MASK: u16 = 0xF << 9;
pub const PM_CTRL_DATA_SCALE_MASK: u16 = 0x3 << 13;
pub const PM_CTRL_PME_STATUS: u16 = 1 << 15;

pub const PM_STATE_D0: u16 = 0;
pub const PM_STATE_D1: u16 = 1;
pub const PM_STATE_D2: u16 = 2;
pub const PM_STATE_D3_HOT: u16 = 3;

pub const MSI_ADDRESS_BASE: u32 = 0xFEE0_0000;
pub const MSI_ADDRESS_DEST_ID_SHIFT: u32 = 12;

pub const MSI_DATA_VECTOR_MASK: u32 = 0xFF;
pub const MSI_DATA_DELIVERY_FIXED: u32 = 0x000;
pub const MSI_DATA_DELIVERY_LOWEST: u32 = 0x100;
pub const MSI_DATA_TRIGGER_EDGE: u32 = 0x000;
pub const MSI_DATA_TRIGGER_LEVEL: u32 = 0x8000;
pub const MSI_DATA_LEVEL_ASSERT: u32 = 0x4000;
pub const MSI_DATA_LEVEL_DEASSERT: u32 = 0x0000;
