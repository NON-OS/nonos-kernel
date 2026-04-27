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

use super::constants::*;
use crate::syscall::SyscallResult;

pub fn ok(value: i64) -> SyscallResult {
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
                    return super::super::errno(17);
                }
                return ok(id as i64);
            }
        }
    }
    if key != IPC_PRIVATE && (msgflg & IPC_CREAT) == 0 {
        return super::super::errno(2);
    }
    if queues.len() as i32 >= MSGMNI {
        return super::super::errno(28);
    }
    let id = MSG_NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let queue = MessageQueue {
        key,
        mode: (msgflg & 0o777) as u16,
        uid: 0,
        gid: 0,
        ctime: crate::time::timestamp_millis(),
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
