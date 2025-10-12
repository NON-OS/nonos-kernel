#![no_std]

extern crate alloc;

use alloc::collections::VecDeque;
use core::sync::atomic::{AtomicU32, Ordering};
use spin::Mutex;

/// round-robin run queue with fixed time slice.
pub struct RunQueue {
    q: Mutex<VecDeque<u32>>,
    current: AtomicU32,        // 0 means "no current"
    slice_left: AtomicU32,     // time-slice ticks remaining for current
    default_slice: u32,        // default time-slice length in ticks
}

impl RunQueue {
    /// new run queue with the given default time slice (ticks).
    pub fn new(default_slice: u32) -> Self {
        Self {
            q: Mutex::new(VecDeque::new()),
            current: AtomicU32::new(0),
            slice_left: AtomicU32::new(0),
            default_slice: default_slice.max(1),
        }
    }

    /// Returns the number of queued (not currently running) tasks.
    #[inline]
    pub fn len(&self) -> usize {
        self.q.lock().len()
    }

    /// Returns true when no task is queued and none is current.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.current.load(Ordering::Relaxed) == 0 && self.q.lock().is_empty()
    }

    /// Returns the currently running pid if any.
    #[inline]
    pub fn current(&self) -> Option<u32> {
        match self.current.load(Ordering::Relaxed) {
            0 => None,
            v => Some(v),
        }
    }

    /// Internal helper: check if pid is enqueued (not counting current).
    fn contains_locked(queue: &VecDeque<u32>, pid: u32) -> bool {
        queue.iter().any(|&p| p == pid)
    }

    /// Enqueue a pid at the back if it's not already queued/current.
    pub fn push(&self, pid: u32) {
        if pid == 0 {
            return;
        }
        if self.current.load(Ordering::Relaxed) == pid {
            return; // already running
        }
        let mut q = self.q.lock();
        if !Self::contains_locked(&q, pid) {
            q.push_back(pid);
        }
    }

    /// Enqueue a pid at the front if not already queued/current (wake-up boost).
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

    /// Remove a pid from the queue (not affecting current). Returns true if found.
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

    /// Deschedule the current pid and clear the current slot 
    /// Returns the pid that was current, if any.
    pub fn clear_current(&self) -> Option<u32> {
        let prev = self.current.swap(0, Ordering::Relaxed);
        if prev != 0 {
            self.slice_left.store(0, Ordering::Relaxed);
            Some(prev)
        } else {
            None
        }
    }

    /// Force a context switch to `pid` (typically used after pick_next()).
    /// Resets the time slice for the new current task.
    pub fn set_current(&self, pid: u32) {
        if pid == 0 {
            return;
        }
        self.current.store(pid, Ordering::Relaxed);
        self.slice_left
            .store(self.default_slice, Ordering::Relaxed);
    }

    /// Yield the current task voluntarily: move it to the back and pick a new one.
    /// Returns the new current pid (if any).
    pub fn yield_current(&self) -> Option<u32> {
        let cur = self.current.swap(0, Ordering::Relaxed);
        if cur != 0 {
            self.push(cur);
        }
        self.pick_next()
    }

    /// Timer tick handler
    pub fn on_timer_tick(&self) -> Option<u32> {
        // No current -> pick next
        if self.current.load(Ordering::Relaxed) == 0 {
            return self.pick_next();
        }

        let left = self.slice_left.load(Ordering::Relaxed);
        if left <= 1 {
            // rotate
            if let Some(cur) = self.clear_current() {
                self.push(cur);
            }
            return self.pick_next();
        } else {
            // keep running, decrement
            self.slice_left
                .store(left - 1, Ordering::Relaxed);
            return self.current();
        }
    }

    /// Pick the next pid from the queue and make it current.
    /// Returns the chosen pid if any.
    pub fn pick_next(&self) -> Option<u32> {
        let mut q = self.q.lock();
        if let Some(next) = q.pop_front() {
            drop(q);
            self.set_current(next);
            Some(next)
        } else {
            // nothing to run
            self.current.store(0, Ordering::Relaxed);
            self.slice_left.store(0, Ordering::Relaxed);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rr_basic_rotation() {
        let rq = RunQueue::new(3);
        rq.push(1);
        rq.push(2);
        rq.push(3);

        // First pick
        let p = rq.pick_next().unwrap();
        assert_eq!(p, 1);

        // 3 ticks -> rotate to 2
        assert_eq!(rq.on_timer_tick(), Some(1));
        assert_eq!(rq.on_timer_tick(), Some(1));
        let p = rq.on_timer_tick().unwrap(); // slice expires
        assert_eq!(p, 2);

        // Next rotation -> 3
        assert_eq!(rq.on_timer_tick(), Some(2));
        assert_eq!(rq.on_timer_tick(), Some(2));
        let p = rq.on_timer_tick().unwrap();
        assert_eq!(p, 3);
    }

    #[test]
    fn no_duplicates() {
        let rq = RunQueue::new(2);
        rq.push(10);
        rq.push(10);
        assert_eq!(rq.len(), 1);
        let _ = rq.pick_next();
        // Already current, push ignored
        rq.push(10);
        assert!(rq.is_empty());
    }

    #[test]
    fn yield_moves_current_to_back() {
        let rq = RunQueue::new(5);
        rq.push(7);
        rq.push(8);
        rq.push(9);
        assert_eq!(rq.pick_next(), Some(7));
        assert_eq!(rq.yield_current(), Some(8));
        // 7 should now be queued after 9
        assert_eq!(rq.yield_current(), Some(9));
        assert_eq!(rq.yield_current(), Some(7));
    }

    #[test]
    fn remove_from_queue() {
        let rq = RunQueue::new(4);
        rq.push(1);
        rq.push(2);
        rq.push(3);
        assert!(rq.remove(2));
        assert_eq!(rq.len(), 2);
        assert!(!rq.remove(2));
    }

    #[test]
    fn clear_current_and_pick() {
        let rq = RunQueue::new(1);
        rq.push(4);
        rq.push(5);
        assert_eq!(rq.pick_next(), Some(4));
        assert_eq!(rq.clear_current(), Some(4));
        // Next should be 5
        assert_eq!(rq.pick_next(), Some(5));
    }
}
