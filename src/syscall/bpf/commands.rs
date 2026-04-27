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

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BpfMapCreate {
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub map_flags: u32,
    pub inner_map_fd: u32,
    pub numa_node: u32,
    pub map_name: [u8; 16],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BpfProgLoad {
    pub prog_type: u32,
    pub insn_cnt: u32,
    pub insns: u64,
    pub license: u64,
    pub log_level: u32,
    pub log_size: u32,
    pub log_buf: u64,
    pub kern_version: u32,
    pub prog_flags: u32,
    pub prog_name: [u8; 16],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BpfMapElem {
    pub map_fd: u32,
    pub key: u64,
    pub value_or_next_key: u64,
    pub flags: u64,
}

impl Default for BpfMapCreate {
    fn default() -> Self {
        Self {
            map_type: 0,
            key_size: 0,
            value_size: 0,
            max_entries: 0,
            map_flags: 0,
            inner_map_fd: 0,
            numa_node: 0,
            map_name: [0; 16],
        }
    }
}

impl Default for BpfProgLoad {
    fn default() -> Self {
        Self {
            prog_type: 0,
            insn_cnt: 0,
            insns: 0,
            license: 0,
            log_level: 0,
            log_size: 0,
            log_buf: 0,
            kern_version: 0,
            prog_flags: 0,
            prog_name: [0; 16],
        }
    }
}

impl Default for BpfMapElem {
    fn default() -> Self {
        Self { map_fd: 0, key: 0, value_or_next_key: 0, flags: 0 }
    }
}
