// This file is part of the NONOS Operating Systems Kernel.
// 
//  Copyright (C) [2025] [NONOS]
//  
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU Affero General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//  
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
//  GNU Affero General Public License for more details.
//
// NØNOS runqueue 
// - Per-CPU multilevel feedback queues (O(1) pick-next via bitmap).
// - 5 public priority bands (Realtime..Idle) mapped into 8 internal levels.
// - Aging to prevent starvation (configurable per level).
// - IRQ-safe enqueue/dequeue; current TID tracking.
// - Sleep/Wake hooks (dequeue + requeue) with optional priority boost.
// - Yield/Rotate helpers.
// - SMP-ready structure; BSP-only instance for now.
// - Proof taps for enqueue/dequeue/choose (public, non-secret).
//
// Zero-state. No persistence. Integrates with task::{on_run_start,on_run_end}.

#![allow(dead_code)]

use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;
use heapless::Deque;

use crate::sched::task::{TaskId, Priority};
use crate::memory::proof::{self, CapTag};

// —————————————————— config ——————————————————

const LEVELS: usize = 8;           // internal levels (0=highest)
const QCAP: usize   = 1024;        // per-level FIFO capacity

// Timeslice (ms) per public band; internal levels derive from band.
pub const TIMESLICE_MS: [u32; 5] = [2, 4, 6, 8, 0]; // Idle=0 => cooperative

// Aging: every AGING_TICKS ticks, bump runnable entities up one level (toward high).
const AGING_TICKS: u32 = 64;

// Mapping band→internal levels (compact and simple for now)
#[inline]
fn level_of(p: Priority) -> usize {
    match p {
        Priority::Realtime => 0,
        Priority::Critical => 0, // Same as realtime
        Priority::High     => 1,
        Priority::Normal   => 3, // leave level 2 for boosted wakes
        Priority::Low      => 5,
        Priority::Idle     => 7,
    }
}
#[inline]
fn band_of_level(l: usize) -> Priority {
    match l {
        0 => Priority::Realtime,
        1 | 2 => Priority::High,
        3 | 4 => Priority::Normal,
        5 | 6 => Priority::Low,
        _ => Priority::Idle,
    }
}

// —————————————————— per-CPU rq ——————————————————

struct CpuRq {
    q: [Deque<TaskId, QCAP>; LEVELS],
    mask: u16,          // bit i set when level i non-empty
    tick_ctr: u32,      // for aging
}
impl CpuRq {
    const fn new() -> Self {
        Self {
            q: [Deque::new(), Deque::new(), Deque::new(), Deque::new(),
                Deque::new(), Deque::new(), Deque::new(), Deque::new()],
            mask: 0,
            tick_ctr: 0,
        }
    }
    #[inline] fn mark(&mut self, lvl: usize) { self.mask |= 1 << lvl; }
    #[inline] fn unmark_if_empty(&mut self, lvl: usize) { if self.q[lvl].is_empty() { self.mask &= !(1 << lvl); } }
    #[inline] fn highest_nonempty(&self) -> Option<usize> {
        // scan 0..LEVELS-1 (tiny), or use bit tricks
        for i in 0..LEVELS { if (self.mask & (1 << i)) != 0 { return Some(i); } }
        None
    }
}

// BSP-only instance for now; move to PERCPU later.
static RQ: Mutex<CpuRq> = Mutex::new(CpuRq::new());
static CURRENT_TID: AtomicU64 = AtomicU64::new(0); // 0 => none/idle

#[inline] pub fn current_tid() -> TaskId { TaskId(CURRENT_TID.load(Ordering::Relaxed)) }
#[inline] pub fn set_current(t: Option<TaskId>) {
    CURRENT_TID.store(t.map(|x| x.0).unwrap_or(0), Ordering::Relaxed);
}

// —————————————————— public API ——————————————————

/// Enqueue at the tail of its level.
/// Use for newly runnable or after voluntary yield; timer-driven rotation uses `rotate_after_run`.
pub fn enqueue(tid: TaskId, prio: Priority) {
    let lvl = level_of(prio);
    let mut rq = RQ.lock();
    let _ = rq.q[lvl].push_back(tid);
    rq.mark(lvl);
    proof::audit_phys_alloc(0x1001, ((tid.0 as u64) << 8) | (lvl as u64), CapTag::KERNEL);
}

/// Dequeue a specific TID from whatever level it currently sits in (O(n) in-band).
pub fn dequeue(tid: TaskId) {
    let mut rq = RQ.lock();
    for lvl in 0..LEVELS {
        if let Some(pos) = rq.q[lvl].iter().position(|&x| x.0 == tid.0) {
            // rotate to front + pop
            for _ in 0..pos {
                let x = rq.q[lvl].pop_front().unwrap();
                let _ = rq.q[lvl].push_back(x);
            }
            let _ = rq.q[lvl].pop_front();
            rq.unmark_if_empty(lvl);
            proof::audit_phys_alloc(0x1002, ((tid.0 as u64) << 8) | (lvl as u64), CapTag::KERNEL);
            return;
        }
    }
}

/// Change priority band (dequeue + enqueue).
pub fn reprioritize(tid: TaskId, new_prio: Priority) {
    dequeue(tid);
    enqueue(tid, new_prio);
}

/// Pick next runnable (highest non-empty level, pop front).
/// Returns None if nothing runnable; the caller should run idle.
pub fn pick_next() -> Option<(TaskId, Priority)> {
    let mut rq = RQ.lock();
    // aging bookkeeping
    rq.tick_ctr = rq.tick_ctr.wrapping_add(1);
    if rq.tick_ctr % AGING_TICKS == 0 { aging_step(&mut rq); }

    let lvl = rq.highest_nonempty()?;
    let tid = rq.q[lvl].pop_front()?;
    rq.unmark_if_empty(lvl);
    let prio = band_of_level(lvl);
    proof::audit_phys_alloc(0x1003, ((tid.0 as u64) << 8) | (lvl as u64), CapTag::KERNEL);
    Some((tid, prio))
}

/// After a time slice, rotate current task to tail of its level (unless it changed).
pub fn rotate_after_run(tid: TaskId, prio: Priority) {
    let lvl = level_of(prio);
    let mut rq = RQ.lock();
    let _ = rq.q[lvl].push_back(tid);
    rq.mark(lvl);
}

/// Cooperative yield: we should place current at tail and select another.
pub fn yield_now(tid: TaskId, prio: Priority) {
    rotate_after_run(tid, prio);
}

/// We put a task to sleep: ensure it’s not on any run queue.
pub fn sleep(tid: TaskId) {
    dequeue(tid);
    // state will be set by scheduler/task layer; so no proof spam here
}

/// Wake a sleeping task: enqueue with optional boost to help tail latency.
pub fn wake(tid: TaskId, base_prio: Priority, boost: bool) {
    if boost {
        // one-level boost if possible (except Realtime)
        let boosted = match base_prio {
            Priority::Realtime => Priority::Realtime,
            Priority::Critical => Priority::Critical, // Can't boost beyond critical
            Priority::High     => Priority::Realtime,
            Priority::Normal   => Priority::High,
            Priority::Low      => Priority::Normal,
            Priority::Idle     => Priority::Low,
        };
        enqueue(tid, boosted);
    } else {
        enqueue(tid, base_prio);
    }
}

// Query how many runnable in each band (for CLI/status)
pub fn stats_counts() -> [usize; 5] {
    let rq = RQ.lock();
    let mut out = [0usize; 5];
    for lvl in 0..LEVELS {
        let band = band_of_level(lvl) as usize;
        out[band] += rq.q[lvl].len();
    }
    out
}

// —————————————————— aging ——————————————————

fn aging_step(rq: &mut CpuRq) {
    // Promote one item from each non-top level to the next higher level.
    for lvl in (1..LEVELS).rev() {
        if let Some(tid) = rq.q[lvl].pop_front() {
            let dest = lvl - 1;
            let _ = rq.q[dest].push_back(tid);
            rq.mark(dest);
            rq.unmark_if_empty(lvl);
            proof::audit_phys_alloc(0x1004, ((tid.0 as u64) << 8) | (dest as u64), CapTag::KERNEL);
        }
    }
}

// —————————————————— helpers ——————————————————

#[inline]
pub fn timeslice_ms_for(prio: Priority) -> u32 {
    match prio {
        Priority::Realtime => TIMESLICE_MS[0],
        Priority::High     => TIMESLICE_MS[1],
        Priority::Normal   => TIMESLICE_MS[2],
        Priority::Low      => TIMESLICE_MS[3],
        Priority::Idle     => TIMESLICE_MS[4],
        Priority::Critical => TIMESLICE_MS[0], // Might be the same as realtime
    }
}
