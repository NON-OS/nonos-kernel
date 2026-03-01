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

use super::state::TASKS;
use super::super::{TaskState, MAX_TASKS};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SchedulerPolicy {
    RoundRobin = 0,
    Priority = 1,
    Fair = 2,
}

impl SchedulerPolicy {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::RoundRobin,
            1 => Self::Priority,
            2 => Self::Fair,
            _ => Self::RoundRobin,
        }
    }
}

pub(super) fn find_next_round_robin(current: usize) -> Option<usize> {
    for offset in 1..=MAX_TASKS {
        let candidate = (current + offset) % MAX_TASKS;
        unsafe {
            if TASKS[candidate].state == TaskState::Ready {
                return Some(candidate);
            }
        }
    }
    None
}

pub(super) fn find_next_priority(current: usize) -> Option<usize> {
    let mut best_candidate: Option<usize> = None;
    let mut best_priority = u8::MAX;

    unsafe {
        for i in 0..MAX_TASKS {
            if TASKS[i].state == TaskState::Ready {
                if TASKS[i].priority < best_priority {
                    best_priority = TASKS[i].priority;
                    best_candidate = Some(i);
                } else if TASKS[i].priority == best_priority {
                    if let Some(bc) = best_candidate {
                        let current_dist = if i > current { i - current } else { MAX_TASKS - current + i };
                        let best_dist = if bc > current { bc - current } else { MAX_TASKS - current + bc };
                        if current_dist < best_dist {
                            best_candidate = Some(i);
                        }
                    }
                }
            }
        }
    }

    best_candidate
}

pub(super) fn find_next_fair(_current: usize) -> Option<usize> {
    let mut best_candidate: Option<usize> = None;
    let mut lowest_runtime = u64::MAX;

    unsafe {
        for i in 0..MAX_TASKS {
            if TASKS[i].state == TaskState::Ready {
                let weight = 256u64 / ((TASKS[i].priority as u64).max(1) + 1);
                let weighted_runtime = TASKS[i].run_time.saturating_mul(weight);

                if weighted_runtime < lowest_runtime {
                    lowest_runtime = weighted_runtime;
                    best_candidate = Some(i);
                }
            }
        }
    }

    best_candidate
}
