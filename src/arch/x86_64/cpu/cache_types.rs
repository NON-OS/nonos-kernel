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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CacheType {
    Null = 0,
    Data = 1,
    Instruction = 2,
    Unified = 3,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CacheLevel {
    pub cache_type: u8,
    pub level: u8,
    pub self_init: bool,
    pub fully_assoc: bool,
    pub max_threads: u16,
    pub max_cores: u16,
    pub line_size: u16,
    pub partitions: u16,
    pub ways: u16,
    pub sets: u32,
    pub size: u32,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct CacheInfo {
    pub l1d_size: u32,
    pub l1d_line_size: u16,
    pub l1d_assoc: u16,
    pub l1i_size: u32,
    pub l1i_line_size: u16,
    pub l1i_assoc: u16,
    pub l2_size: u32,
    pub l2_line_size: u16,
    pub l2_assoc: u16,
    pub l3_size: u32,
    pub l3_line_size: u16,
    pub l3_assoc: u16,
    pub line_size: u16,
}
