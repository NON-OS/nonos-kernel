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

use alloc::collections::VecDeque;
use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

pub struct RunQueue {
    q: Mutex<VecDeque<u32>>,
    current: AtomicU32,
    slice_left: AtomicU32,
    default_slice: u32,
}

impl RunQueue {
    pub fn new(default_slice: u32) -> Self {
        Self {
            q: Mutex::new(VecDeque::new()),
            current: AtomicU32::new(0),
            slice_left: AtomicU32::new(0),
            default_slice: default_slice.max(1),
        }
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.q.lock().len()
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.current.load(Ordering::Relaxed) == 0 && self.q.lock().is_empty()
    }

    #[inline]
    pub fn current(&self) -> Option<u32> {
        match self.current.load(Ordering::Relaxed) {
            0 => None,
            v => Some(v),
        }
    }

    fn contains_locked(queue: &VecDeque<u32>, pid: u32) -> bool {
        queue.iter().any(|&p| p == pid)
    }

    pub fn push(&self, pid: u32) {
        if pid == 0 {
            return;
        }
        if self.current.load(Ordering::Relaxed) == pid {
            return;
        }
        let mut q = self.q.lock();
        if !Self::contains_locked(&q, pid) {
            q.push_back(pid);
        }
    }

    pub fn push_front(&self, pid: u32) {
        if pid == 0 {
            return;
        }
        if self.current.load(Ordering::Relaxed) == pid {
            return;
        }
        let mut q = self.q.lock();
        if !Self::contains_locked(&q, pid) {
            q.push_front(pid);
        }
    }

    pub fn remove(&self, pid: u32) -> bool {
        if pid == 0 {
            return false;
        }
        let mut q = self.q.lock();
        if let Some(pos) = q.iter().position(|&p| p == pid) {
            q.remove(pos);
            true
        } else {
            false
        }
    }

    pub fn clear_current(&self) -> Option<u32> {
        let prev = self.current.swap(0, Ordering::Relaxed);
        if prev != 0 {
            self.slice_left.store(0, Ordering::Relaxed);
            Some(prev)
        } else {
            None
        }
    }

    pub fn set_current(&self, pid: u32) {
        if pid == 0 {
            return;
        }
        self.current.store(pid, Ordering::Relaxed);
        self.slice_left.store(self.default_slice, Ordering::Relaxed);
    }

    pub fn yield_current(&self) -> Option<u32> {
        let cur = self.current.swap(0, Ordering::Relaxed);
        if cur != 0 {
            self.push(cur);
        }
        self.pick_next()
    }

    pub fn on_timer_tick(&self) -> Option<u32> {
        if self.current.load(Ordering::Relaxed) == 0 {
            return self.pick_next();
        }

        let left = self.slice_left.load(Ordering::Relaxed);
        if left <= 1 {
            if let Some(cur) = self.clear_current() {
                self.push(cur);
            }
            return self.pick_next();
        } else {
            self.slice_left.store(left - 1, Ordering::Relaxed);
            return self.current();
        }
    }

    pub fn pick_next(&self) -> Option<u32> {
        let mut q = self.q.lock();
        if let Some(next) = q.pop_front() {
            drop(q);
            self.set_current(next);
            Some(next)
        } else {
            self.current.store(0, Ordering::Relaxed);
            self.slice_left.store(0, Ordering::Relaxed);
            None
        }
    }
}
