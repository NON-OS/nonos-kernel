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

pub mod pm1_status {
    pub const TMR_STS: u16 = 1 << 0;
    pub const BM_STS: u16 = 1 << 4;
    pub const GBL_STS: u16 = 1 << 5;
    pub const PWRBTN_STS: u16 = 1 << 8;
    pub const SLPBTN_STS: u16 = 1 << 9;
    pub const RTC_STS: u16 = 1 << 10;
    pub const PCIEXP_WAKE_STS: u16 = 1 << 14;
    pub const WAK_STS: u16 = 1 << 15;
}

pub mod pm1_enable {
    pub const TMR_EN: u16 = 1 << 0;
    pub const GBL_EN: u16 = 1 << 5;
    pub const PWRBTN_EN: u16 = 1 << 8;
    pub const SLPBTN_EN: u16 = 1 << 9;
    pub const RTC_EN: u16 = 1 << 10;
    pub const PCIEXP_WAKE_DIS: u16 = 1 << 14;
}

pub mod pm1_control {
    pub const SCI_EN: u16 = 1 << 0;
    pub const BM_RLD: u16 = 1 << 1;
    pub const GBL_RLS: u16 = 1 << 2;
    pub const SLP_TYP_SHIFT: u16 = 10;
    pub const SLP_TYP_MASK: u16 = 0x07 << SLP_TYP_SHIFT;
    pub const SLP_EN: u16 = 1 << 13;
}
