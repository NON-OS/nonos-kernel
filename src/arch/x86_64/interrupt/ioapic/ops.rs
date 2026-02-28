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

use alloc::vec::Vec;

use crate::memory::proof::{self, CapTag};
use super::error::{IoApicError, IoApicResult};
use super::types::{Rte, IsoFlags};
use super::state::*;
use super::mmio::{redtbl_read, redtbl_write};

pub fn claim_gsi_for_msi(gsi: u32) {
    let mut claimed = MSI_CLAIMED.lock();
    if (gsi as usize) < claimed.len() {
        claimed.set(gsi as usize, true);
    }
}

pub fn release_gsi_from_msi(gsi: u32) {
    let mut claimed = MSI_CLAIMED.lock();
    if (gsi as usize) < claimed.len() {
        claimed.set(gsi as usize, false);
    }
}

fn is_gsi_claimed(gsi: u32) -> bool {
    let claimed = MSI_CLAIMED.lock();
    (gsi as usize) < claimed.len() && claimed[gsi as usize]
}

pub fn alloc_route(gsi: u32, dest_apic_id: u32) -> IoApicResult<(u8, Rte)> {
    if is_gsi_claimed(gsi) {
        return Err(IoApicError::GsiClaimedForMsi);
    }

    let vector = VEC_ALLOC.lock().alloc().ok_or(IoApicError::VectorExhausted)?;
    let mut rte = Rte::fixed(vector, dest_apic_id);

    if let Some(flags) = iso_flags_for(gsi) {
        if flags.contains(IsoFlags::TRIGGER_LEVEL) {
            rte.level_trigger = true;
        }
        if flags.contains(IsoFlags::POLARITY_ACTIVE_LOW) {
            rte.active_low = true;
        }
    }

    Ok((vector, rte))
}

pub fn program_route(gsi: u32, rte: Rte) -> IoApicResult<()> {
    let (chip, idx) = locate(gsi).ok_or(IoApicError::GsiNotFound)?;
    let (low, high) = rte.to_u32s();

    unsafe { redtbl_write(chip.mmio, idx, low, high); }

    proof::audit_phys_alloc(
        ((gsi as u64) << 32) | rte.vector as u64,
        ((rte.dest_apic_id as u64) << 32) | rte.flags_bits() as u64,
        CapTag::KERNEL,
    );

    Ok(())
}

pub fn mask(gsi: u32, masked: bool) -> IoApicResult<()> {
    let (chip, idx) = locate(gsi).ok_or(IoApicError::GsiNotFound)?;

    unsafe {
        let (mut low, high) = redtbl_read(chip.mmio, idx);
        if masked {
            low |= 1 << 16;
        } else {
            low &= !(1 << 16);
        }
        redtbl_write(chip.mmio, idx, low, high);
    }

    Ok(())
}

pub fn retarget(gsi: u32, dest_apic_id: u32) -> IoApicResult<()> {
    let (chip, idx) = locate(gsi).ok_or(IoApicError::GsiNotFound)?;

    unsafe {
        let (low, mut high) = redtbl_read(chip.mmio, idx);
        high &= !(0xFF << 24);
        high |= (dest_apic_id & 0xFF) << 24;
        redtbl_write(chip.mmio, idx, low, high);
    }

    Ok(())
}

pub fn free_vector(vec: u8) {
    VEC_ALLOC.lock().free(vec);
}

pub fn query(gsi: u32) -> Option<Rte> {
    let (chip, idx) = locate(gsi)?;
    let (low, high) = unsafe { redtbl_read(chip.mmio, idx) };
    Some(Rte::from_u32s(low, high))
}

pub fn snapshot() -> Vec<(u32, Rte)> {
    let mut out = Vec::new();
    let chips = IOAPICS.lock();

    for chip in chips.iter().flatten() {
        for i in 0..chip.redirs {
            let (low, high) = unsafe { redtbl_read(chip.mmio, i) };
            out.push((chip.gsi_base + i, Rte::from_u32s(low, high)));
        }
    }

    out
}

pub fn restore(snap: &[(u32, Rte)]) {
    for (gsi, rte) in snap {
        let _ = program_route(*gsi, Rte { masked: true, ..*rte });
    }
}

#[derive(Debug, Clone)]
pub struct IoApicStatus {
    pub initialized: bool,
    pub count: usize,
    pub total_gsis: u32,
}

pub fn status() -> IoApicStatus {
    let chips = IOAPICS.lock();
    let mut total_gsis = 0u32;

    for chip in chips.iter().flatten() {
        total_gsis += chip.redirs;
    }

    IoApicStatus {
        initialized: is_initialized(),
        count: count(),
        total_gsis,
    }
}

fn iso_flags_for(gsi: u32) -> Option<IsoFlags> {
    let cache = ISO.lock();
    cache.iso.iter().find(|e| e.gsi == gsi).map(|e| e.flags)
}

fn locate(gsi: u32) -> Option<(IoApicChip, u32)> {
    let chips = IOAPICS.lock();
    for chip in chips.iter().flatten() {
        let end = chip.gsi_base + chip.redirs;
        if gsi >= chip.gsi_base && gsi < end {
            return Some((*chip, gsi - chip.gsi_base));
        }
    }
    None
}
