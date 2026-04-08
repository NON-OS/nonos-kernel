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
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use crate::capsule::CapsuleId;
use super::{queue, router, types::*};

static MSG_COUNTER: AtomicU64 = AtomicU64::new(1);

pub fn init() {
    queue::init_queues();
    router::init_router();
    crate::sys::boot_log::ok("CAPSULE_IPC", "Messaging service ready");
}

pub fn register(id: CapsuleId) { queue::create_queue(id); }
pub fn unregister(id: CapsuleId) { queue::destroy_queue(id); }

fn next_id() -> u64 { MSG_COUNTER.fetch_add(1, Ordering::Relaxed) }

pub fn send(src: CapsuleId, dst: CapsuleId, mt: MsgType, payload: Vec<u8>) -> Result<u64, MsgError> {
    let msg = CapsuleMsg::new(next_id(), src, dst, mt, payload);
    router::check_route(&msg)?;
    queue::enqueue(dst, msg.clone())?;
    Ok(msg.id)
}

pub fn send_data(src: CapsuleId, dst: CapsuleId, payload: Vec<u8>) -> Result<u64, MsgError> {
    send(src, dst, MsgType::Data, payload)
}

pub fn send_request(src: CapsuleId, dst: CapsuleId, payload: Vec<u8>) -> Result<u64, MsgError> {
    send(src, dst, MsgType::Request, payload)
}

pub fn recv(id: CapsuleId) -> Result<CapsuleMsg, MsgError> { queue::dequeue(id) }
pub fn peek(id: CapsuleId) -> Option<CapsuleMsg> { queue::peek(id) }
pub fn pending(id: CapsuleId) -> usize { queue::queue_len(id) }

pub fn connect(a: CapsuleId, b: CapsuleId) { router::allow_all(a, b); }
pub fn disconnect(a: CapsuleId, b: CapsuleId) { router::deny_all(a, b); }
