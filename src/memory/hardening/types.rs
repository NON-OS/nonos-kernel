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

//! Memory Hardening Types

use x86_64::VirtAddr;

/// Guard page descriptor.
#[derive(Debug, Clone, Copy)]
pub struct GuardPage {
    /// Virtual address of guard page.
    pub addr: VirtAddr,
    /// Size of guard region.
    pub size: usize,
    /// Type of guard protection.
    pub protection_type: GuardType,
}

/// Type of guard page protection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardType {
    /// Stack guard page.
    StackGuard,
    /// Heap guard page.
    HeapGuard,
    /// Kernel memory guard.
    KernelGuard,
    /// User memory guard.
    UserGuard,
}

/// Stack canary descriptor.
#[derive(Debug)]
pub struct StackCanary {
    /// Canary value.
    pub value: u64,
    /// Stack base address.
    pub stack_base: VirtAddr,
    /// Stack size.
    pub stack_size: usize,
}

/// Allocation tracking information.
#[derive(Debug, Clone)]
pub struct AllocationInfo {
    /// Size of allocation.
    pub size: usize,
    /// Timestamp of allocation.
    pub timestamp: u64,
    /// Unique allocation ID.
    pub allocation_id: u64,
    /// Whether this allocation has been freed.
    pub freed: bool,
}

/// Hardening statistics snapshot.
#[derive(Debug)]
pub struct HardeningStatsSnapshot {
    /// Number of guard page violations.
    pub guard_violations: u64,
    /// Number of W^X violations.
    pub wx_violations: u64,
    /// Number of stack overflows detected.
    pub stack_overflows: u64,
    /// Number of heap corruptions detected.
    pub heap_corruptions: u64,
    /// Number of double frees prevented.
    pub double_frees: u64,
    /// Number of use-after-free detected.
    pub use_after_free: u64,
    /// Total number of guard pages.
    pub total_guard_pages: usize,
    /// Number of active stack canaries.
    pub active_canaries: usize,
    /// Number of tracked allocations.
    pub tracked_allocations: usize,
}
