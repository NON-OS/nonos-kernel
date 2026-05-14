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

pub const fn cap_mqes(cap: u64) -> u16 {
    ((cap & 0xffff) as u16).saturating_add(1)
}

pub const fn cap_to(cap: u64) -> u8 {
    ((cap >> 24) & 0xff) as u8
}

pub const fn cap_dstrd(cap: u64) -> u8 {
    ((cap >> 32) & 0x0f) as u8
}

pub const fn cap_nvm_supported(cap: u64) -> bool {
    ((cap >> 37) & 0x01) != 0
}

pub const fn cap_mpsmin_shift(cap: u64) -> u8 {
    (((cap >> 48) & 0x0f) as u8) + 12
}

pub const fn cap_mpsmax_shift(cap: u64) -> u8 {
    (((cap >> 52) & 0x0f) as u8) + 12
}
