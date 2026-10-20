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

use core::sync::atomic::Ordering;

use super::request::{REQ_PAGES, REQ_PENDING_ACKS, REQ_VA};

/// What every CPU looked like when the round gave up, printed before the halt.
/// A timeout says only that an ack did not arrive; which cpu owed it, whether
/// it was marked, and whether it is idle or in a handler separate "the IPI was
/// never delivered" from "the cpu was in no position to run it". The head
/// line's va and pages (0 for a whole flush) name the change that waited.
pub(super) fn report_stuck() {
    let mut head = crate::sys::serial::Line::new();
    head.str(b"[SMP] acks outstanding=").dec(REQ_PENDING_ACKS.load(Ordering::Acquire) as u64);
    head.str(b" va=").hex(REQ_VA.load(Ordering::Acquire));
    head.str(b" pages=").dec(REQ_PAGES.load(Ordering::Acquire) as u64);
    head.end();
    #[cfg(target_arch = "x86_64")]
    report_unclaimed_nmis();
    for cpu in 0..crate::smp::MAX_CPUS {
        if !crate::smp::cpu_is_online(cpu) {
            continue;
        }
        let (Some(d), Some(desc)) = (crate::smp::percpu::get(cpu), crate::smp::get_cpu(cpu)) else {
            continue;
        };
        /*
         * One line per cpu, built whole, so it does not interleave with the
         * other cpus still printing. `irq_depth` comes from
         * `interrupts::safety`, which the live handlers maintain; the old
         * `irq_nesting` and disable-depth columns had no writers and read
         * zero on every dump, so they are gone rather than reported.
         */
        let mut l = crate::sys::serial::Line::new();
        l.str(b"[SMP]  cpu=").dec(cpu as u64);
        l.str(b" apic=").dec(d.apic_id as u64);
        l.str(b" pending=").dec(d.tlb_flush_pending.load(Ordering::Acquire) as u64);
        l.str(b" irq_depth=").dec(crate::interrupts::safety::depth_of(cpu) as u64);
        l.str(b" asid=").dec(d.active_asid.load(Ordering::Acquire) as u64);
        l.str(b" idle=").dec(u64::from(desc.idle.load(Ordering::Acquire)));
        l.str(b" idle_cycles=").dec(desc.idle_cycles.load(Ordering::Acquire));
        // Zero means this cpu has never taken a timer interrupt, which
        // separates "did not answer this round" from "has not answered
        // anything since it came up". Those need different fixes and the dump
        // could not tell them apart.
        l.str(b" ticked=").dec(u64::from(d.last_tick_tsc.load(Ordering::Acquire) != 0));
        // Where it was when it stopped answering. A halted CPU and one
        // spinning on a lock with interrupts masked are the same silence from
        // here, and they are not the same defect.
        l.str(b" at=").str(desc.stage().as_str().as_bytes());
        // What that CPU's own APIC had in service when it last looked. A vector
        // stuck here blocks its whole priority class and everything below it,
        // while leaving higher classes working, which is what a CPU taking
        // IPIs at 0x40 and no timer at 0x20 looks like from outside.
        match desc.in_service_seen.load(Ordering::Acquire) {
            0 => l.str(b" isr=unread"),
            1 => l.str(b" isr=none"),
            v => l.str(b" isr=").hex((v - 2) as u64),
        };
        l.end();
    }
}

#[cfg(target_arch = "x86_64")]
fn report_unclaimed_nmis() {
    let nmi = crate::interrupts::handlers::exceptions::nmi_record::nmi_counts();
    let mut nl = crate::sys::serial::Line::new();
    nl.str(b"[SMP] nmi unclaimed parity=").dec(nmi.memory_parity);
    nl.str(b" iochk=").dec(nmi.io_channel_check).str(b" watchdog=").dec(nmi.watchdog);
    nl.str(b" unknown=").dec(nmi.unknown).str(b" last_rip=").hex(nmi.last_rip);
    nl.end();
}
