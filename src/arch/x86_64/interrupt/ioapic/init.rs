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
use x86_64::PhysAddr;

use crate::memory::virt::VmFlags;
use crate::memory::layout::PAGE_SIZE;
use crate::memory::proof::{self, CapTag};
use super::constants::*;
use super::error::{IoApicError, IoApicResult};
use super::types::{MadtIoApic, MadtIso, MadtNmi};
use super::state::*;
use super::mmio::{map_mmio, reg_read};

pub unsafe fn init(ioapics: &[MadtIoApic], iso: &[MadtIso], nmis: &[MadtNmi]) -> IoApicResult<()> {
    unsafe {
        if INITIALIZED.swap(true, Ordering::SeqCst) {
            return Err(IoApicError::AlreadyInitialized);
        }

        {
            let mut cache = ISO.lock();
            cache.iso.extend_from_slice(iso);
            cache.nmis.extend_from_slice(nmis);
        }

        let mut chips = IOAPICS.lock();
        let mut n = 0usize;

        for desc in ioapics.iter().take(MAX_IOAPIC) {
            let va = map_mmio(PhysAddr::new(desc.phys_base))?;
            let ver = reg_read(va, IOAPICVER);
            let maxredir = ((ver >> 16) & 0xFF) + 1;

            chips[n] = Some(IoApicChip {
                gsi_base: desc.gsi_base,
                redirs: maxredir,
                mmio: va,
            });
            n += 1;

            proof::audit_map(
                va.as_u64(),
                desc.phys_base,
                PAGE_SIZE as u64,
                (VmFlags::RW | VmFlags::NX | VmFlags::GLOBAL | VmFlags::PCD).bits(),
                CapTag::KERNEL,
            );

            crate::log::logger::log_info!(
                "[IOAPIC] phys=0x{:x} gsi_base={} redirs={}",
                desc.phys_base, desc.gsi_base, maxredir
            );
        }

        COUNT.store(n, Ordering::Release);

        {
            let mut va = VEC_ALLOC.lock();
            va.reserve(crate::arch::x86_64::interrupt::apic::VEC_TIMER);
            va.reserve(crate::arch::x86_64::interrupt::apic::VEC_THERMAL);
            va.reserve(crate::arch::x86_64::interrupt::apic::VEC_ERROR);
        }

        Ok(())
    }
}
