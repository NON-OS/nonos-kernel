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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    Idle = 0,
    Low = 1,
    Normal = 2,
    High = 3,
    Critical = 4,
    RealTime = 5,
}

#[derive(Debug, Clone)]
pub struct CpuAffinity {
    pub allowed_cpus: alloc::vec::Vec<u32>,
}

impl CpuAffinity {
    pub fn any() -> Self {
        Self { allowed_cpus: (0..16).collect() }
    }

    pub fn new(cpus: alloc::vec::Vec<u32>) -> Self {
        Self { allowed_cpus: cpus }
    }
}

pub struct Task {
    pub id: u64,
    pub name: &'static str,
    pub func: Option<fn()>,
    pub priority: Priority,
    pub affinity: CpuAffinity,
    pub complete: bool,
    pub module_id: Option<u64>,
    pub entry_point: u64,
    pub stack_pointer: u64,
}

impl Task {
    pub fn run(&mut self) {
        if let Some(func) = self.func {
            func();
        } else if self.entry_point != 0 {
            // SAFETY: Module entry point is validated during module loading.
            unsafe {
                let entry: extern "C" fn() = core::mem::transmute(self.entry_point as usize);
                entry();
            }
        }
        self.complete = true;
    }

    pub fn is_complete(&self) -> bool {
        self.complete
    }

    pub fn spawn(name: &'static str, func: fn(), priority: Priority, affinity: CpuAffinity) -> Self {
        Self {
            id: 0,
            name,
            func: Some(func),
            priority,
            affinity,
            complete: false,
            module_id: None,
            entry_point: 0,
            stack_pointer: 0,
        }
    }

    pub fn new_module_task(
        task_id: u64,
        module_id: u64,
        entry_point: u64,
        stack_pointer: u64,
        priority: u8,
    ) -> Self {
        let prio = match priority {
            0..=50 => Priority::Low,
            51..=100 => Priority::Normal,
            101..=150 => Priority::High,
            151..=200 => Priority::Critical,
            _ => Priority::RealTime,
        };

        Self {
            id: task_id,
            name: "module_task",
            func: None,
            priority: prio,
            affinity: CpuAffinity::any(),
            complete: false,
            module_id: Some(module_id),
            entry_point,
            stack_pointer,
        }
    }
}
