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

extern crate alloc;

use super::super::errno;
use super::constants::*;
use super::msg_types::{ok, Message, MSG_QUEUES};
use crate::syscall::SyscallResult;
use crate::usercopy::{copy_from_user, copy_to_user, read_user_value, write_user_value};

pub fn handle_msgsnd(msqid: i32, msgp: u64, msgsz: u64, msgflg: i32) -> SyscallResult {
    if msgp == 0 {
        return errno(14);
    }
    let msgsz = msgsz as usize;
    if msgsz > MSGMAX {
        return errno(22);
    }
    let pid = crate::process::current_pid().unwrap_or(0);
    let mtype: i64 = match read_user_value(msgp) {
        Ok(v) => v,
        Err(_) => return errno(14),
    };
    if mtype <= 0 {
        return errno(22);
    }
    let mut data = alloc::vec![0u8; msgsz];
    if copy_from_user(msgp + 8, &mut data).is_err() {
        return errno(14);
    }
    loop {
        let mut queues = MSG_QUEUES.lock();
        let queue = match queues.get_mut(&msqid) {
            Some(q) => q,
            None => return errno(22),
        };
        let current_bytes: usize = queue.messages.iter().map(|m| m.data.len()).sum();
        if current_bytes + msgsz <= queue.qbytes {
            queue.messages.push_back(Message { mtype, data });
            queue.qnum += 1;
            queue.stime = crate::time::timestamp_millis();
            queue.lspid = pid;
            return ok(0);
        }
        drop(queues);
        if (msgflg & IPC_NOWAIT) != 0 {
            return errno(11);
        }
        crate::sched::yield_cpu();
    }
}

pub fn handle_msgrcv(msqid: i32, msgp: u64, msgsz: u64, msgtyp: i64, msgflg: i32) -> SyscallResult {
    if msgp == 0 {
        return errno(14);
    }
    let msgsz = msgsz as usize;
    let pid = crate::process::current_pid().unwrap_or(0);
    loop {
        let mut queues = MSG_QUEUES.lock();
        let queue = match queues.get_mut(&msqid) {
            Some(q) => q,
            None => return errno(22),
        };
        let msg_index = find_message_index(queue, msgtyp, msgflg);
        if let Some(idx) = msg_index {
            let msg = match queue.messages.remove(idx) {
                Some(m) => m,
                None => continue,
            };
            queue.qnum = queue.qnum.saturating_sub(1);
            queue.rtime = crate::time::timestamp_millis();
            queue.lrpid = pid;
            let copy_size = if msg.data.len() > msgsz {
                if (msgflg & MSG_NOERROR) != 0 {
                    msgsz
                } else {
                    queue.messages.push_front(msg);
                    queue.qnum += 1;
                    return errno(34);
                }
            } else {
                msg.data.len()
            };
            if write_user_value(msgp, &msg.mtype).is_err() {
                return errno(14);
            }
            if copy_to_user(msgp + 8, &msg.data[..copy_size]).is_err() {
                return errno(14);
            }
            return ok(copy_size as i64);
        }
        drop(queues);
        if (msgflg & IPC_NOWAIT) != 0 {
            return errno(42);
        }
        crate::sched::yield_cpu();
    }
}

fn find_message_index(
    queue: &super::msg_types::MessageQueue,
    msgtyp: i64,
    msgflg: i32,
) -> Option<usize> {
    if msgtyp == 0 {
        if !queue.messages.is_empty() {
            Some(0)
        } else {
            None
        }
    } else if msgtyp > 0 {
        if (msgflg & MSG_EXCEPT) != 0 {
            queue.messages.iter().position(|m| m.mtype != msgtyp)
        } else {
            queue.messages.iter().position(|m| m.mtype == msgtyp)
        }
    } else {
        let max_type = -msgtyp;
        queue
            .messages
            .iter()
            .enumerate()
            .filter(|(_, m)| m.mtype <= max_type)
            .min_by_key(|(_, m)| m.mtype)
            .map(|(i, _)| i)
    }
}
