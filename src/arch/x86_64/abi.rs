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

//! x86_64 backend for [`ArchOps`].

use core::arch::asm;

use crate::arch::abi::ArchOps;
use crate::memory::addr::{PhysAddr, VirtAddr};

/// Zero-sized backend type. Generic code links to it through the
/// `Arch` alias in `crate::arch`.
pub struct X86_64;

impl ArchOps for X86_64 {
    #[inline(always)]
    fn halt() -> ! {
        loop {
            unsafe {
                asm!("cli; hlt", options(nostack, preserves_flags));
            }
        }
    }

    #[inline(always)]
    unsafe fn enable_interrupts() {
        asm!("sti", options(nostack, preserves_flags));
    }

    #[inline(always)]
    unsafe fn disable_interrupts() {
        asm!("cli", options(nostack, preserves_flags));
    }

    #[inline(always)]
    fn interrupts_enabled() -> bool {
        let rflags: u64;
        unsafe {
            asm!("pushfq; pop {}", out(reg) rflags, options(nomem, preserves_flags));
        }
        // RFLAGS bit 9 is IF.
        rflags & (1 << 9) != 0
    }

    // A uniprocessor boot already knows the answer, and answering from
    // memory matters: CPUID is an unconditional VM exit under hardware
    // virtualization, and this call sits on the syscall dispatch, timer
    // tick and context switch paths, so the exits dominate guest time.
    #[inline(always)]
    fn current_cpu_id() -> u32 {
        if let Some(id) = crate::smp::sole_cpu_apic_id() {
            return id;
        }
        // The APIC id from CPUID, the value the descriptor table was filled
        // from and the IPI path addresses. Leaf 1 EBX[31:24] is only the low
        // byte of it: on a part with ids past 255, or in x2APIC mode, that
        // byte names some other CPU, and the lookup would either halt this one
        // as unregistered or hand it another CPU's state. Leaf 0x0B carries
        // the full 32-bit id; `cpuid_apic_id` picks it whenever it exists.
        /*
         * The shared helper restores RBX by exchange, which stays correct
         * when the compiler picks RBX for the output; a push/pop pair would
         * hand back the caller's RBX, a stack address, as the APIC id.
         */
        cpuid_apic_id()
    }

    #[inline(always)]
    fn read_time_counter() -> u64 {
        // RDTSC reads the time-stamp counter into EDX:EAX. Modern
        // x86_64 CPUs run an invariant TSC; calibration to wall time
        // happens elsewhere in `sys::timer::tsc`.
        let lo: u32;
        let hi: u32;
        unsafe {
            asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags));
        }
        ((hi as u64) << 32) | (lo as u64)
    }

    #[inline(always)]
    unsafe fn flush_tlb_one(addr: VirtAddr) {
        asm!("invlpg [{}]", in(reg) addr.as_u64(), options(nostack, preserves_flags));
    }

    #[inline(always)]
    unsafe fn switch_address_space(root: PhysAddr) {
        asm!("mov cr3, {}", in(reg) root.as_u64(), options(nostack, preserves_flags));
    }
}

/// Whether leaf 0x0B is implemented: 0 not yet asked, 1 yes, 2 no. Settled on
/// first use and identical on every CPU of a machine, so a race to set it
/// writes the same answer twice.
static LEAF_0B: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);

#[inline]
fn cpuid_apic_id() -> u32 {
    use crate::arch::x86_64::interrupt::apic::plan::apic_id_from_cpuid;
    use crate::arch::x86_64::time::tsc::cpuid;
    use core::sync::atomic::Ordering;
    match LEAF_0B.load(Ordering::Relaxed) {
        1 => cpuid(0x0B, 0).3,
        2 => cpuid(1, 0).1 >> 24,
        _ => {
            let max = cpuid(0, 0).0;
            let (_, ebx_b, _, edx_b) = if max >= 0x0B { cpuid(0x0B, 0) } else { (0, 0, 0, 0) };
            let leaf1 = cpuid(1, 0).1;
            let usable = max >= 0x0B && ebx_b & 0xFFFF != 0;
            LEAF_0B.store(if usable { 1 } else { 2 }, Ordering::Relaxed);
            apic_id_from_cpuid(max, ebx_b, edx_b, leaf1)
        }
    }
}
