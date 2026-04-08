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

pub const SMI_EN_OFFSET: u16 = 0x30;
pub const SMI_STS_OFFSET: u16 = 0x34;

pub mod smi_en {
    pub const GBL_SMI_EN: u32 = 1 << 0;
    pub const EOS: u32 = 1 << 1;
    pub const BIOS_EN: u32 = 1 << 2;
    pub const LEGACY_USB_EN: u32 = 1 << 3;
    pub const SLP_SMI_EN: u32 = 1 << 4;
    pub const APMC_EN: u32 = 1 << 5;
    pub const SWSMI_TMR_EN: u32 = 1 << 6;
    pub const BIOS_RLS: u32 = 1 << 7;
    pub const TCO_EN: u32 = 1 << 13;
    pub const PERIODIC_EN: u32 = 1 << 14;
    pub const SERIRQ_SMI_EN: u32 = 1 << 15;
    pub const SMBUS_SMI_EN: u32 = 1 << 16;
    pub const GPIO_EN: u32 = 1 << 18;
    pub const USB_EN: u32 = 1 << 19;
}
