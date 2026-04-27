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

/// # Safety
/// KernelMode represents trusted execution contexts where the kernel has
/// full control. Only kernel code paths should set these modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelMode {
    Boot,
    Interrupt,
    Scheduler,
    Driver,
}

/// # Safety
/// ProcessContext stores security-critical data including capability bits
/// and page table root. The page_table_root must point to valid page tables
/// owned by this process. Capability bits must not be elevated without
/// proper privilege checks.
#[derive(Debug, Clone, Copy)]
pub struct ProcessContext {
    pub pid: u32,
    pub capabilities: u64,
    pub page_table_root: u64,
}

impl ProcessContext {
    /// # Safety
    /// Caller must ensure pid is valid, capabilities are authorized,
    /// and page_table_root points to valid mapped page tables.
    pub fn new(pid: u32, capabilities: u64, page_table_root: u64) -> Self {
        Self { pid, capabilities, page_table_root }
    }

    pub fn has_capability(&self, cap: u64) -> bool {
        (self.capabilities & cap) == cap
    }
}

/// # Safety
/// ExecutionContext determines privilege level for all kernel operations.
/// Incorrect context can lead to privilege escalation. The None variant
/// must deny all privileged operations - never grant implicit access.
#[derive(Debug, Clone, Copy)]
pub enum ExecutionContext {
    None,
    Kernel(KernelMode),
    Process(ProcessContext),
}

impl ExecutionContext {
    pub fn is_kernel(&self) -> bool {
        matches!(self, Self::Kernel(_))
    }

    pub fn is_process(&self) -> bool {
        matches!(self, Self::Process(_))
    }

    pub fn process(&self) -> Option<&ProcessContext> {
        match self {
            Self::Process(ctx) => Some(ctx),
            _ => None,
        }
    }

    pub fn kernel_mode(&self) -> Option<KernelMode> {
        match self {
            Self::Kernel(mode) => Some(*mode),
            _ => None,
        }
    }
}
