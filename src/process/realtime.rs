//! Real-time Scheduling Extensions
//!
//! Real-time scheduling with priority inheritance and deadline scheduling

use crate::process::process::ProcessId;
use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};

/// Real-time scheduling policy
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RtPolicy {
    Fifo,       // SCHED_FIFO - run until blocked or preempted
    RoundRobin, // SCHED_RR - time-sliced round robin
    Deadline,   // SCHED_DEADLINE - earliest deadline first
}

/// Real-time process descriptor
#[derive(Debug, Clone)]
pub struct RtProcess {
    pub pid: ProcessId,
    pub policy: RtPolicy,
    pub priority: u8,          // RT priority (0-99)
    pub time_slice: u32,       // For RR policy
    pub deadline: Option<u64>, // Absolute deadline
    pub period: Option<u64>,   // Period for periodic tasks
    pub wcet: Option<u64>,     // Worst-case execution time
}

/// Priority inheritance chain
#[derive(Debug)]
pub struct PriorityInheritanceChain {
    pub blocked_task: ProcessId,
    pub blocking_task: ProcessId,
    pub inherited_priority: u8,
    pub original_priority: u8,
    pub resource: String,
}

/// Real-time scheduler extensions
pub struct RealTimeScheduler {
    rt_processes: BTreeMap<ProcessId, RtProcess>,
    priority_chains: Vec<PriorityInheritanceChain>,
    deadline_queue: Vec<(u64, ProcessId)>, // (deadline, pid)

    // Statistics
    missed_deadlines: AtomicU64,
    priority_inversions: AtomicU64,
}

impl RealTimeScheduler {
    pub fn new() -> Self {
        RealTimeScheduler {
            rt_processes: BTreeMap::new(),
            priority_chains: Vec::new(),
            deadline_queue: Vec::new(),
            missed_deadlines: AtomicU64::new(0),
            priority_inversions: AtomicU64::new(0),
        }
    }

    /// Add real-time process
    pub fn add_rt_process(&mut self, rt_proc: RtProcess) {
        if let Some(deadline) = rt_proc.deadline {
            self.deadline_queue.push((deadline, rt_proc.pid));
            self.deadline_queue.sort_by_key(|(d, _)| *d);
        }

        self.rt_processes.insert(rt_proc.pid, rt_proc);
    }

    /// Handle priority inheritance
    pub fn handle_priority_inheritance(
        &mut self,
        blocked_pid: ProcessId,
        blocking_pid: ProcessId,
        resource: String,
    ) {
        if let (Some(blocked), Some(blocking)) =
            (self.rt_processes.get(&blocked_pid), self.rt_processes.get(&blocking_pid))
        {
            if blocked.priority > blocking.priority {
                // Priority inversion detected
                self.priority_inversions.fetch_add(1, Ordering::Relaxed);

                let chain = PriorityInheritanceChain {
                    blocked_task: blocked_pid,
                    blocking_task: blocking_pid,
                    inherited_priority: blocked.priority,
                    original_priority: blocking.priority,
                    resource,
                };

                self.priority_chains.push(chain);
            }
        }
    }

    /// Get next deadline task
    pub fn next_deadline_task(&mut self) -> Option<ProcessId> {
        let current_time = crate::time::timestamp_millis();

        // Check for missed deadlines
        while let Some(&(deadline, pid)) = self.deadline_queue.first() {
            if deadline <= current_time {
                self.deadline_queue.remove(0);
                self.missed_deadlines.fetch_add(1, Ordering::Relaxed);
                continue;
            } else {
                return Some(pid);
            }
        }

        None
    }
}
