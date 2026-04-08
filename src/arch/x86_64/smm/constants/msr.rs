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

pub mod amd_msr {
    pub const SMM_BASE: u32 = 0xC001_0111;
    pub const SMM_ADDR: u32 = 0xC001_0112;
    pub const SMM_MASK: u32 = 0xC001_0113;
    pub const LOCK_BIT: u64 = 0x2;
}

pub mod intel_msr {
    pub const IA32_FEATURE_CONTROL: u32 = 0x3A;
    pub const SMM_FEATURE_CONTROL: u32 = 0x4E0;
    pub const SMM_CODE_CHK_EN: u64 = 0x1;
    pub const SMM_BWP: u64 = 0x2;
}

pub mod cr4 {
    pub const SMEP: u64 = 1 << 20;
    pub const SMAP: u64 = 1 << 21;
}
