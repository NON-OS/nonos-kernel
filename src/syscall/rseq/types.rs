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
#[derive(Debug, Clone, Copy, Default)]
pub struct Rseq {
    pub cpu_id_start: u32,
    pub cpu_id: u32,
    pub rseq_cs: u64,
    pub flags: u32,
    pub node_id: u32,
    pub mm_cid: u32,
    pub padding: [u32; 3],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct RseqCs {
    pub version: u32,
    pub flags: u32,
    pub start_ip: u64,
    pub post_commit_offset: u64,
    pub abort_ip: u64,
}

#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RseqFlags {
    None = 0,
    Unregister = 1,
    RegisterOnAbi = 2,
}

impl Rseq {
    pub const SIZE: usize = core::mem::size_of::<Self>();
    pub const SIZE_V1: u32 = 32;
    pub const SIZE_V2: u32 = 32;
    pub const SIZE_V3: u32 = 48;

    pub fn new() -> Self {
        Self {
            cpu_id_start: 0,
            cpu_id: crate::smp::current_cpu_id() as u32,
            rseq_cs: 0,
            flags: 0,
            node_id: 0,
            mm_cid: 0,
            padding: [0; 3],
        }
    }

    pub fn update_cpu(&mut self) {
        self.cpu_id = crate::smp::current_cpu_id() as u32;
    }
}

impl RseqCs {
    pub const SIZE: usize = core::mem::size_of::<Self>();

    pub fn is_valid(&self) -> bool {
        self.version == 0 && self.start_ip != 0 && self.abort_ip != 0
    }
}
