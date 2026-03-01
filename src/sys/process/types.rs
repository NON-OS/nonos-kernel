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

pub const MAX_TASKS: usize = 32;
pub const TASK_STACK_SIZE: usize = 64 * 1024;

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    Empty = 0,
    Ready = 1,
    Running = 2,
    Blocked = 3,
    Sleeping = 4,
    Terminated = 5,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CpuContext {
    pub rbx: u64,
    pub rbp: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rsp: u64,
    pub rip: u64,
    pub rflags: u64,
}

impl CpuContext {
    pub const fn empty() -> Self {
        Self {
            rbx: 0, rbp: 0, r12: 0, r13: 0, r14: 0, r15: 0,
            rsp: 0, rip: 0, rflags: 0x202,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Task {
    pub id: u32,
    pub state: TaskState,
    pub name: [u8; 32],
    pub name_len: u8,
    pub context: CpuContext,
    pub stack_base: u64,
    pub stack_size: usize,
    pub priority: u8,
    pub sleep_until: u64,
    pub parent_id: u32,
    pub exit_code: i32,
    pub run_time: u64,
    pub last_scheduled: u64,
    pub switch_count: u64,
}

impl Task {
    pub const fn empty() -> Self {
        Self {
            id: 0,
            state: TaskState::Empty,
            name: [0u8; 32],
            name_len: 0,
            context: CpuContext::empty(),
            stack_base: 0,
            stack_size: 0,
            priority: 128,
            sleep_until: 0,
            parent_id: 0,
            exit_code: 0,
            run_time: 0,
            last_scheduled: 0,
            switch_count: 0,
        }
    }

    pub fn set_name(&mut self, name: &[u8]) {
        let len = name.len().min(31);
        self.name[..len].copy_from_slice(&name[..len]);
        self.name_len = len as u8;
    }

    pub fn get_name(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}

pub fn state_str(state: TaskState) -> &'static [u8] {
    match state {
        TaskState::Empty => b"empty",
        TaskState::Ready => b"ready",
        TaskState::Running => b"running",
        TaskState::Blocked => b"blocked",
        TaskState::Sleeping => b"sleeping",
        TaskState::Terminated => b"zombie",
    }
}
