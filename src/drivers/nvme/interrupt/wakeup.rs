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

use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

pub static COMPLETION_WAITERS: Mutex<WaiterSlots> = Mutex::new(WaiterSlots::new());
static COMPLETION_COUNTER: AtomicU64 = AtomicU64::new(0);

pub struct WaiterSlots {
    cid: [u16; 64],
    queue_id: [u16; 64],
    completed: [bool; 64],
    active: [bool; 64],
}

impl WaiterSlots {
    const fn new() -> Self {
        Self { cid: [0; 64], queue_id: [0; 64], completed: [false; 64], active: [false; 64] }
    }
}

pub fn signal_completion(queue_id: u16, cid: u16) {
    let mut waiters = COMPLETION_WAITERS.lock();
    for i in 0..64 {
        if waiters.active[i] && waiters.queue_id[i] == queue_id && waiters.cid[i] == cid {
            waiters.completed[i] = true;
            break;
        }
    }
    COMPLETION_COUNTER.fetch_add(1, Ordering::Release);
}

pub fn wait_for_signal(queue_id: u16, cid: u16, timeout_spins: u32) -> bool {
    let slot = {
        let mut waiters = COMPLETION_WAITERS.lock();
        let slot = (0..64).find(|&i| !waiters.active[i]);
        if let Some(idx) = slot {
            waiters.cid[idx] = cid;
            waiters.queue_id[idx] = queue_id;
            waiters.completed[idx] = false;
            waiters.active[idx] = true;
        }
        slot
    };
    let Some(idx) = slot else { return spin_wait_fallback(timeout_spins) };
    let result = spin_until_complete(idx, timeout_spins);
    COMPLETION_WAITERS.lock().active[idx] = false;
    result
}

fn spin_until_complete(slot: usize, timeout: u32) -> bool {
    for _ in 0..timeout {
        if COMPLETION_WAITERS.lock().completed[slot] {
            return true;
        }
        core::hint::spin_loop();
    }
    false
}

fn spin_wait_fallback(timeout: u32) -> bool {
    for _ in 0..timeout {
        core::hint::spin_loop();
    }
    true
}
