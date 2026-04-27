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

use super::super::errno;
use super::constants::*;
use super::shm_types::{ok, SHM_SEGMENTS};
use crate::syscall::SyscallResult;
use crate::usercopy::{copy_from_user, copy_to_user};

pub fn handle_shmctl(shmid: i32, cmd: i32, buf: u64) -> SyscallResult {
    let mut segments = SHM_SEGMENTS.lock();
    match cmd {
        IPC_RMID => handle_rmid(&mut segments, shmid),
        IPC_STAT | SHM_STAT => handle_stat(&segments, shmid, buf),
        IPC_SET => handle_set(&mut segments, shmid, buf),
        SHM_INFO => handle_info(&segments, buf),
        _ => errno(22),
    }
}

fn handle_rmid(
    segments: &mut alloc::collections::BTreeMap<i32, super::shm_types::ShmSegment>,
    shmid: i32,
) -> SyscallResult {
    if let Some(segment) = segments.get_mut(&shmid) {
        if segment.nattch == 0 {
            segments.remove(&shmid);
        } else {
            segment.marked_for_removal = true;
        }
        ok(0)
    } else {
        errno(22)
    }
}

fn handle_stat(
    segments: &alloc::collections::BTreeMap<i32, super::shm_types::ShmSegment>,
    shmid: i32,
    buf: u64,
) -> SyscallResult {
    if buf == 0 {
        return errno(14);
    }
    if let Some(segment) = segments.get(&shmid) {
        let mut stat_buf = [0u8; 88];
        stat_buf[0..8].copy_from_slice(&segment.key.to_ne_bytes());
        stat_buf[8..16].copy_from_slice(&(segment.uid as u64).to_ne_bytes());
        stat_buf[16..24].copy_from_slice(&(segment.gid as u64).to_ne_bytes());
        stat_buf[24..32].copy_from_slice(&(segment.mode as u64).to_ne_bytes());
        stat_buf[32..40].copy_from_slice(&(segment.size as u64).to_ne_bytes());
        stat_buf[40..48].copy_from_slice(&segment.atime.to_ne_bytes());
        stat_buf[48..56].copy_from_slice(&segment.dtime.to_ne_bytes());
        stat_buf[56..64].copy_from_slice(&segment.ctime.to_ne_bytes());
        stat_buf[64..72].copy_from_slice(&(segment.cpid as u64).to_ne_bytes());
        stat_buf[72..80].copy_from_slice(&(segment.lpid as u64).to_ne_bytes());
        stat_buf[80..88].copy_from_slice(&(segment.nattch as u64).to_ne_bytes());
        if copy_to_user(buf, &stat_buf).is_err() {
            return errno(14);
        }
        ok(0)
    } else {
        errno(22)
    }
}

fn handle_set(
    segments: &mut alloc::collections::BTreeMap<i32, super::shm_types::ShmSegment>,
    shmid: i32,
    buf: u64,
) -> SyscallResult {
    if buf == 0 {
        return errno(14);
    }
    if let Some(segment) = segments.get_mut(&shmid) {
        let mut set_buf = [0u8; 32];
        if copy_from_user(buf, &mut set_buf).is_err() {
            return errno(14);
        }
        // SAFETY: Safe array conversions from fixed-size buffer - return EINVAL on any failure
        segment.uid = u64::from_ne_bytes(match set_buf[8..16].try_into() {
            Ok(arr) => arr,
            Err(_) => return errno(22),
        }) as u32;
        segment.gid = u64::from_ne_bytes(match set_buf[16..24].try_into() {
            Ok(arr) => arr,
            Err(_) => return errno(22),
        }) as u32;
        segment.mode = u64::from_ne_bytes(match set_buf[24..32].try_into() {
            Ok(arr) => arr,
            Err(_) => return errno(22),
        }) as u16;
        segment.ctime = crate::time::timestamp_millis();
        ok(0)
    } else {
        errno(22)
    }
}

fn handle_info(
    segments: &alloc::collections::BTreeMap<i32, super::shm_types::ShmSegment>,
    buf: u64,
) -> SyscallResult {
    if buf == 0 {
        return errno(14);
    }
    let mut info_buf = [0u8; 24];
    info_buf[0..8].copy_from_slice(&(segments.len() as u64).to_ne_bytes());
    info_buf[8..16].copy_from_slice(&(SHMMAX as u64).to_ne_bytes());
    info_buf[16..24].copy_from_slice(&(SHMMNI as u64).to_ne_bytes());
    if copy_to_user(buf, &info_buf).is_err() {
        return errno(14);
    }
    ok(segments.len() as i64)
}
