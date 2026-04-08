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

use alloc::collections::BinaryHeap;
use core::cmp::Ordering;
use core::sync::atomic::{AtomicBool, Ordering as AO};
use spin::{Mutex, Once};
use crate::sched::task::{Task, DeadlineFlags};
use super::types::{AdmissionError, DeadlineStats};
use super::admission::can_admit;

pub(super) struct DeadlineTask { pub task: Task }

impl DeadlineTask {
    fn abs_deadline(&self) -> u64 {
        self.task.deadline_params.as_ref().map(|d| d.abs_deadline).unwrap_or(u64::MAX)
    }
}

impl PartialEq for DeadlineTask { fn eq(&self, o: &Self) -> bool { self.abs_deadline() == o.abs_deadline() } }
impl Eq for DeadlineTask {}
impl PartialOrd for DeadlineTask { fn partial_cmp(&self, o: &Self) -> Option<Ordering> { Some(self.cmp(o)) } }
impl Ord for DeadlineTask { fn cmp(&self, o: &Self) -> Ordering { o.abs_deadline().cmp(&self.abs_deadline()) } }

pub(super) struct DeadlineScheduler {
    pub runqueue: BinaryHeap<DeadlineTask>,
    pub total_bandwidth: u64,
    pub active_count: u64,
    pub stats: DeadlineStats,
}

static SCHEDULER: Once<Mutex<DeadlineScheduler>> = Once::new();
pub(super) static INITIALIZED: AtomicBool = AtomicBool::new(false);

pub(super) fn get_scheduler() -> &'static Mutex<DeadlineScheduler> {
    SCHEDULER.call_once(|| Mutex::new(DeadlineScheduler {
        runqueue: BinaryHeap::new(), total_bandwidth: 0, active_count: 0, stats: DeadlineStats::default()
    }))
}

pub fn init() { get_scheduler().lock().runqueue.clear(); INITIALIZED.store(true, AO::SeqCst); }

pub fn spawn_deadline(mut task: Task) -> Result<(), AdmissionError> {
    if !INITIALIZED.load(AO::SeqCst) { return Err(AdmissionError::NotInitialized); }
    let params = task.deadline_params.as_ref().ok_or(AdmissionError::InvalidParameters)?;
    can_admit(params)?;
    let bw = params.bandwidth();
    let now = crate::sys::clock::get_ticks();
    if let Some(ref mut dl) = task.deadline_params {
        dl.period_start = now; dl.abs_deadline = now + dl.deadline;
        dl.remaining_runtime = dl.runtime; dl.flags.insert(DeadlineFlags::DL_NEW);
    }
    let mut s = get_scheduler().lock();
    s.total_bandwidth += bw; s.active_count += 1;
    s.stats.activations.fetch_add(1, AO::Relaxed);
    s.runqueue.push(DeadlineTask { task });
    Ok(())
}
