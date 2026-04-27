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

use super::types::{MqAttr, MqMessage, MQ_MAXMSG_DEFAULT, MQ_MSGSIZE_DEFAULT};
use alloc::collections::{BTreeMap, BinaryHeap};
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI32, Ordering};
use spin::Mutex;

static NEXT_MQFD: AtomicI32 = AtomicI32::new(100);
static QUEUES: Mutex<BTreeMap<String, MessageQueue>> = Mutex::new(BTreeMap::new());
static FD_MAP: Mutex<BTreeMap<i32, String>> = Mutex::new(BTreeMap::new());

pub struct MessageQueue {
    pub name: String,
    pub attr: MqAttr,
    pub messages: BinaryHeap<MqMessage>,
    pub mode: u32,
}

impl MessageQueue {
    pub fn new(name: String, attr: MqAttr, mode: u32) -> Self {
        Self { name, attr, messages: BinaryHeap::new(), mode }
    }

    pub fn open(name: &str, flags: i32, mode: u32, attr: Option<MqAttr>) -> Result<i32, i32> {
        let mut queues = QUEUES.lock();
        let create = flags & 0o100 != 0;
        let excl = flags & 0o200 != 0;
        if let Some(_) = queues.get(name) {
            if create && excl {
                return Err(17);
            }
        } else if create {
            let mqattr = attr.unwrap_or_else(|| MqAttr::new(MQ_MAXMSG_DEFAULT, MQ_MSGSIZE_DEFAULT));
            mqattr.validate()?;
            queues.insert(String::from(name), MessageQueue::new(String::from(name), mqattr, mode));
        } else {
            return Err(2);
        }
        let fd = NEXT_MQFD.fetch_add(1, Ordering::SeqCst);
        FD_MAP.lock().insert(fd, String::from(name));
        Ok(fd)
    }

    pub fn unlink(name: &str) -> Result<(), i32> {
        QUEUES.lock().remove(name).map(|_| ()).ok_or(2)
    }

    pub fn send(fd: i32, msg: Vec<u8>, priority: u32) -> Result<(), i32> {
        let name = FD_MAP.lock().get(&fd).cloned().ok_or(9)?;
        let mut queues = QUEUES.lock();
        let queue = queues.get_mut(&name).ok_or(9)?;
        if msg.len() > queue.attr.mq_msgsize as usize {
            return Err(90);
        }
        if queue.messages.len() >= queue.attr.mq_maxmsg as usize {
            return Err(11);
        }
        queue.messages.push(MqMessage::new(msg, priority));
        queue.attr.mq_curmsgs = queue.messages.len() as i64;
        Ok(())
    }

    pub fn receive(fd: i32) -> Result<(Vec<u8>, u32), i32> {
        let name = FD_MAP.lock().get(&fd).cloned().ok_or(9)?;
        let mut queues = QUEUES.lock();
        let queue = queues.get_mut(&name).ok_or(9)?;
        let msg = queue.messages.pop().ok_or(11)?;
        queue.attr.mq_curmsgs = queue.messages.len() as i64;
        Ok((msg.data, msg.priority))
    }

    pub fn getattr(fd: i32) -> Result<MqAttr, i32> {
        let name = FD_MAP.lock().get(&fd).cloned().ok_or(9)?;
        let queues = QUEUES.lock();
        let queue = queues.get(&name).ok_or(9)?;
        Ok(queue.attr)
    }

    pub fn setattr(fd: i32, attr: &MqAttr) -> Result<MqAttr, i32> {
        let name = FD_MAP.lock().get(&fd).cloned().ok_or(9)?;
        let mut queues = QUEUES.lock();
        let queue = queues.get_mut(&name).ok_or(9)?;
        let old = queue.attr;
        queue.attr.mq_flags = attr.mq_flags;
        Ok(old)
    }
}
