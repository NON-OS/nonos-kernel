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

use alloc::collections::{BTreeMap, VecDeque};
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, Ordering};
use spin::Mutex;

use crate::syscall::SyscallResult;
use super::super::errno;
use super::constants::*;

fn ok(value: i64) -> SyscallResult {
    SyscallResult { value, capability_consumed: false, audit_required: false }
}

#[derive(Clone)]
pub struct Message {
    pub mtype: i64,
    pub data: Vec<u8>,
}

#[derive(Clone)]
pub struct MessageQueue {
    pub key: u64,
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub ctime: u64,
    pub stime: u64,
    pub rtime: u64,
    pub lspid: u32,
    pub lrpid: u32,
    pub qbytes: usize,
    pub qnum: usize,
    pub messages: VecDeque<Message>,
}

pub static MSG_QUEUES: Mutex<BTreeMap<i32, MessageQueue>> = Mutex::new(BTreeMap::new());
pub static MSG_NEXT_ID: AtomicI32 = AtomicI32::new(1);

pub fn handle_msgget(key: u64, msgflg: i32) -> SyscallResult {
    let mut queues = MSG_QUEUES.lock();

    if key != IPC_PRIVATE {
        for (&id, queue) in queues.iter() {
            if queue.key == key {
                if (msgflg & IPC_CREAT) != 0 && (msgflg & IPC_EXCL) != 0 {
                    return errno(17);
                }
                return ok(id as i64);
            }
        }
    }

    if key != IPC_PRIVATE && (msgflg & IPC_CREAT) == 0 {
        return errno(2);
    }

    if queues.len() as i32 >= MSGMNI {
        return errno(28);
    }

    let id = MSG_NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let now = crate::time::timestamp_millis();

    let queue = MessageQueue {
        key,
        mode: (msgflg & 0o777) as u16,
        uid: 0,
        gid: 0,
        ctime: now,
        stime: 0,
        rtime: 0,
        lspid: 0,
        lrpid: 0,
        qbytes: MSGMNB,
        qnum: 0,
        messages: VecDeque::new(),
    };

    queues.insert(id, queue);
    ok(id as i64)
}

pub fn handle_msgsnd(msqid: i32, msgp: u64, msgsz: u64, msgflg: i32) -> SyscallResult {
    if msgp == 0 {
        return errno(14);
    }

    let msgsz = msgsz as usize;
    if msgsz > MSGMAX {
        return errno(22);
    }

    let pid = crate::process::current_pid().unwrap_or(0);

    // SAFETY: msgp is user-provided pointer to message struct.
    let mtype = unsafe { core::ptr::read(msgp as *const i64) };
    if mtype <= 0 {
        return errno(22);
    }

    // SAFETY: msgp is user-provided pointer to message struct.
    let data = unsafe {
        let ptr = (msgp + 8) as *const u8;
        core::slice::from_raw_parts(ptr, msgsz).to_vec()
    };

    loop {
        let mut queues = MSG_QUEUES.lock();

        let queue = match queues.get_mut(&msqid) {
            Some(q) => q,
            None => return errno(22),
        };

        let current_bytes: usize = queue.messages.iter().map(|m| m.data.len()).sum();
        if current_bytes + msgsz <= queue.qbytes {
            let now = crate::time::timestamp_millis();
            queue.messages.push_back(Message {
                mtype,
                data,
            });
            queue.qnum += 1;
            queue.stime = now;
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

        let msg_index = if msgtyp == 0 {
            if !queue.messages.is_empty() { Some(0) } else { None }
        } else if msgtyp > 0 {
            if (msgflg & MSG_EXCEPT) != 0 {
                queue.messages.iter().position(|m| m.mtype != msgtyp)
            } else {
                queue.messages.iter().position(|m| m.mtype == msgtyp)
            }
        } else {
            let max_type = -msgtyp;
            queue.messages.iter()
                .enumerate()
                .filter(|(_, m)| m.mtype <= max_type)
                .min_by_key(|(_, m)| m.mtype)
                .map(|(i, _)| i)
        };

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

            // SAFETY: msgp is user-provided pointer for message struct.
            unsafe {
                core::ptr::write(msgp as *mut i64, msg.mtype);
                let data_ptr = (msgp + 8) as *mut u8;
                core::ptr::copy_nonoverlapping(msg.data.as_ptr(), data_ptr, copy_size);
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
        IPC_STAT | MSG_STAT => {
            if buf == 0 {
                return errno(14);
            }
            if let Some(queue) = queues.get(&msqid) {
                // SAFETY: buf is user-provided pointer for msqid_ds struct.
                unsafe {
                    let ptr = buf as *mut u64;
                    core::ptr::write(ptr.add(0), queue.key);
                    core::ptr::write(ptr.add(1), queue.uid as u64);
                    core::ptr::write(ptr.add(2), queue.gid as u64);
                    core::ptr::write(ptr.add(3), queue.mode as u64);
                    core::ptr::write(ptr.add(4), queue.stime);
                    core::ptr::write(ptr.add(5), queue.rtime);
                    core::ptr::write(ptr.add(6), queue.ctime);
                    core::ptr::write(ptr.add(7), queue.qnum as u64);
                    core::ptr::write(ptr.add(8), queue.qbytes as u64);
                    core::ptr::write(ptr.add(9), queue.lspid as u64);
                    core::ptr::write(ptr.add(10), queue.lrpid as u64);
                }
                ok(0)
            } else {
                errno(22)
            }
        }
        IPC_SET => {
            if buf == 0 {
                return errno(14);
            }
            if let Some(queue) = queues.get_mut(&msqid) {
                // SAFETY: buf is user-provided pointer for msqid_ds struct.
                unsafe {
                    let ptr = buf as *const u64;
                    queue.uid = core::ptr::read(ptr.add(1)) as u32;
                    queue.gid = core::ptr::read(ptr.add(2)) as u32;
                    queue.mode = core::ptr::read(ptr.add(3)) as u16;
                    queue.qbytes = core::ptr::read(ptr.add(8)) as usize;
                }
                queue.ctime = crate::time::timestamp_millis();
                ok(0)
            } else {
                errno(22)
            }
        }
        MSG_INFO => {
            if buf == 0 {
                return errno(14);
            }
            let total_messages: usize = queues.values().map(|q| q.qnum).sum();
            // SAFETY: buf is user-provided pointer for msginfo struct.
            unsafe {
                let ptr = buf as *mut u64;
                core::ptr::write(ptr.add(0), queues.len() as u64);
                core::ptr::write(ptr.add(1), total_messages as u64);
                core::ptr::write(ptr.add(2), MSGMAX as u64);
                core::ptr::write(ptr.add(3), MSGMNB as u64);
                core::ptr::write(ptr.add(4), MSGMNI as u64);
            }
            ok(queues.len() as i64)
        }
        _ => errno(22),
    }
}
