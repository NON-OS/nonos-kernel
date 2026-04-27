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
use super::msg_types::{ok, MSG_QUEUES};
use crate::syscall::SyscallResult;
use crate::usercopy::{copy_from_user, copy_to_user};

pub fn handle_msgctl(msqid: i32, cmd: i32, buf: u64) -> SyscallResult {
    let mut queues = MSG_QUEUES.lock();
    match cmd {
        IPC_RMID => {
            if queues.remove(&msqid).is_some() {
                ok(0)
            } else {
                errno(22)
            }
        }
        IPC_STAT | MSG_STAT => handle_msg_stat(&queues, msqid, buf),
        IPC_SET => handle_msg_set(&mut queues, msqid, buf),
        MSG_INFO => handle_msg_info(&queues, buf),
        _ => errno(22),
    }
}

fn handle_msg_stat(
    queues: &alloc::collections::BTreeMap<i32, super::msg_types::MessageQueue>,
    msqid: i32,
    buf: u64,
) -> SyscallResult {
    if buf == 0 {
        return errno(14);
    }
    if let Some(queue) = queues.get(&msqid) {
        let mut stat_buf = [0u8; 88];
        stat_buf[0..8].copy_from_slice(&queue.key.to_ne_bytes());
        stat_buf[8..16].copy_from_slice(&(queue.uid as u64).to_ne_bytes());
        stat_buf[16..24].copy_from_slice(&(queue.gid as u64).to_ne_bytes());
        stat_buf[24..32].copy_from_slice(&(queue.mode as u64).to_ne_bytes());
        stat_buf[32..40].copy_from_slice(&queue.stime.to_ne_bytes());
        stat_buf[40..48].copy_from_slice(&queue.rtime.to_ne_bytes());
        stat_buf[48..56].copy_from_slice(&queue.ctime.to_ne_bytes());
        stat_buf[56..64].copy_from_slice(&(queue.qnum as u64).to_ne_bytes());
        stat_buf[64..72].copy_from_slice(&(queue.qbytes as u64).to_ne_bytes());
        stat_buf[72..80].copy_from_slice(&(queue.lspid as u64).to_ne_bytes());
        stat_buf[80..88].copy_from_slice(&(queue.lrpid as u64).to_ne_bytes());
        if copy_to_user(buf, &stat_buf).is_err() {
            return errno(14);
        }
        ok(0)
    } else {
        errno(22)
    }
}

fn handle_msg_set(
    queues: &mut alloc::collections::BTreeMap<i32, super::msg_types::MessageQueue>,
    msqid: i32,
    buf: u64,
) -> SyscallResult {
    if buf == 0 {
        return errno(14);
    }
    if let Some(queue) = queues.get_mut(&msqid) {
        let mut set_buf = [0u8; 72];
        if copy_from_user(buf, &mut set_buf).is_err() {
            return errno(14);
        }
        // SAFETY: Safe array conversions from fixed-size buffer - return EINVAL on any failure
        queue.uid = u64::from_ne_bytes(match set_buf[8..16].try_into() {
            Ok(arr) => arr,
            Err(_) => return errno(22),
        }) as u32;
        queue.gid = u64::from_ne_bytes(match set_buf[16..24].try_into() {
            Ok(arr) => arr,
            Err(_) => return errno(22),
        }) as u32;
        queue.mode = u64::from_ne_bytes(match set_buf[24..32].try_into() {
            Ok(arr) => arr,
            Err(_) => return errno(22),
        }) as u16;
        queue.qbytes = u64::from_ne_bytes(match set_buf[64..72].try_into() {
            Ok(arr) => arr,
            Err(_) => return errno(22),
        }) as usize;
        queue.ctime = crate::time::timestamp_millis();
        ok(0)
    } else {
        errno(22)
    }
}

fn handle_msg_info(
    queues: &alloc::collections::BTreeMap<i32, super::msg_types::MessageQueue>,
    buf: u64,
) -> SyscallResult {
    if buf == 0 {
        return errno(14);
    }
    let total_messages: usize = queues.values().map(|q| q.qnum).sum();
    let mut info_buf = [0u8; 40];
    info_buf[0..8].copy_from_slice(&(queues.len() as u64).to_ne_bytes());
    info_buf[8..16].copy_from_slice(&(total_messages as u64).to_ne_bytes());
    info_buf[16..24].copy_from_slice(&(MSGMAX as u64).to_ne_bytes());
    info_buf[24..32].copy_from_slice(&(MSGMNB as u64).to_ne_bytes());
    info_buf[32..40].copy_from_slice(&(MSGMNI as u64).to_ne_bytes());
    if copy_to_user(buf, &info_buf).is_err() {
        return errno(14);
    }
    ok(queues.len() as i64)
}
