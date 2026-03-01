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

#[repr(C, packed)]
pub struct GdtEntry {
    pub limit_low: u16,
    pub base_low: u16,
    pub base_mid: u8,
    pub access: u8,
    pub granularity: u8,
    pub base_high: u8,
}

#[repr(C, packed)]
pub struct GdtPtr {
    pub limit: u16,
    pub base: u64,
}

pub static mut GDT: [GdtEntry; 3] = [
    GdtEntry {
        limit_low: 0,
        base_low: 0,
        base_mid: 0,
        access: 0,
        granularity: 0,
        base_high: 0,
    },
    GdtEntry {
        limit_low: 0xFFFF,
        base_low: 0,
        base_mid: 0,
        access: 0x9A,
        granularity: 0xAF,
        base_high: 0,
    },
    GdtEntry {
        limit_low: 0xFFFF,
        base_low: 0,
        base_mid: 0,
        access: 0x92,
        granularity: 0xCF,
        base_high: 0,
    },
];
