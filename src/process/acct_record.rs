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

pub const AFORK: u8 = 0x01;
pub const ASU: u8 = 0x02;
pub const ACORE: u8 = 0x08;
pub const AXSIG: u8 = 0x10;

#[derive(Clone, Copy, Default)]
pub struct AcctRecord {
    pub ac_flag: u8,
    pub ac_version: u8,
    pub ac_tty: u16,
    pub ac_exitcode: u32,
    pub ac_uid: u32,
    pub ac_gid: u32,
    pub ac_pid: u32,
    pub ac_ppid: u32,
    pub ac_btime: u32,
    pub ac_etime: f32,
    pub ac_utime: f32,
    pub ac_stime: f32,
    pub ac_mem: f32,
    pub ac_io: f32,
    pub ac_rw: f32,
    pub ac_minflt: f32,
    pub ac_majflt: f32,
    pub ac_swaps: f32,
    pub ac_comm: [u8; 16],
}
