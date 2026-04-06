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

pub const fn make_dev(major: u32, minor: u32) -> u64 {
    ((major as u64) << 8) | (minor as u64 & 0xff) | ((minor as u64 & 0xfff00) << 12)
}

pub const fn major(dev: u64) -> u32 {
    ((dev >> 8) & 0xfff) as u32
}

pub const fn minor(dev: u64) -> u32 {
    ((dev & 0xff) | ((dev >> 12) & 0xfff00)) as u32
}

pub const MEM_MAJOR: u32 = 1;
pub const TTY_MAJOR: u32 = 4;
pub const TTYAUX_MAJOR: u32 = 5;
pub const LP_MAJOR: u32 = 6;
pub const VCS_MAJOR: u32 = 7;
pub const LOOP_MAJOR: u32 = 7;
pub const SCSI_DISK_MAJOR: u32 = 8;
pub const MISC_MAJOR: u32 = 10;
pub const INPUT_MAJOR: u32 = 13;
pub const SOUND_MAJOR: u32 = 14;
pub const USB_CHAR_MAJOR: u32 = 180;
pub const UNIX98_PTY_MASTER_MAJOR: u32 = 128;
pub const UNIX98_PTY_SLAVE_MAJOR: u32 = 136;
pub const BLOCK_EXT_MAJOR: u32 = 259;

pub const NULL_MINOR: u32 = 3;
pub const ZERO_MINOR: u32 = 5;
pub const FULL_MINOR: u32 = 7;
pub const RANDOM_MINOR: u32 = 8;
pub const URANDOM_MINOR: u32 = 9;
pub const KMSG_MINOR: u32 = 11;

pub fn dev_name_to_major_minor(name: &str) -> Option<(u32, u32)> {
    match name {
        "null" => Some((MEM_MAJOR, NULL_MINOR)),
        "zero" => Some((MEM_MAJOR, ZERO_MINOR)),
        "full" => Some((MEM_MAJOR, FULL_MINOR)),
        "random" => Some((MEM_MAJOR, RANDOM_MINOR)),
        "urandom" => Some((MEM_MAJOR, URANDOM_MINOR)),
        "tty" => Some((TTYAUX_MAJOR, 0)),
        "console" => Some((TTYAUX_MAJOR, 1)),
        "ptmx" => Some((TTYAUX_MAJOR, 2)),
        _ => None,
    }
}
