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

//! Arch-leaf primitives.
//!
//! Generic kernel code calls these methods through the active
//! `Arch` type alias instead of reaching into per-arch modules.
//! Adding a new architecture means writing a new backend type that
//! implements `ArchOps`; the cfg-gated `Arch` alias in
//! `crate::arch::mod` selects which backend the build links.
//!
//! H1 Phase 1 ships eight leaf primitives. IRQ vector allocation,
//! MMIO/PIO/DMA grants, the syscall entry path, and the per-arch
//! timer device live behind their own boundary in Phase 2.

use crate::memory::addr::{PhysAddr, VirtAddr};

/// Eight leaf primitives every NØNOS-supported architecture must
/// provide. Functions are infallible; an arch backend that cannot
/// implement one yet must not have an `ArchOps` impl at all, so a
/// build for that arch fails to link rather than silently doing the
/// wrong thing.
pub trait ArchOps {
    /// Halt the calling CPU forever.
    fn halt() -> !;

    /// Enable interrupts on the calling CPU.
    ///
    /// # Safety
    ///
    /// Reordering this against an in-progress critical section can
    /// open a race. Callers must reason about IRQ-masked invariants.
    unsafe fn enable_interrupts();

    /// Disable interrupts on the calling CPU.
    ///
    /// # Safety
    ///
    /// Pairs with [`enable_interrupts`]. Disabling without a matching
    /// enable strands the CPU.
    unsafe fn disable_interrupts();

    /// True iff interrupts are currently enabled on the calling CPU.
    fn interrupts_enabled() -> bool;

    /// Identifier of the CPU executing the call. Stable for the
    /// lifetime of that CPU.
    fn current_cpu_id() -> u32;

    /// Monotonic per-CPU tick counter. The unit is platform-defined
    /// (TSC ticks on x86_64, generic timer counter on aarch64, mtime
    /// on riscv64); callers that need wall-clock time go through
    /// `sys::clock` instead.
    fn read_time_counter() -> u64;

    /// Invalidate the TLB entry covering `addr` on the calling CPU.
    ///
    /// # Safety
    ///
    /// Stale entries elsewhere in the system stay live until those
    /// CPUs flush. Cross-CPU shootdown is the SMP layer's
    /// responsibility, not this primitive's.
    unsafe fn flush_tlb_one(addr: VirtAddr);

    /// Replace the page-table root pointer for the calling CPU.
    ///
    /// # Safety
    ///
    /// `root` must point at a valid top-level page table for this
    /// arch. Switching mid-instruction without an identity-mapped
    /// fallback faults.
    unsafe fn switch_address_space(root: PhysAddr);
}
