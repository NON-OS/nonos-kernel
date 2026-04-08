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

use crate::memory::proof::{self, CapTag};
use super::error::{IoApicError, IoApicResult};
use super::types::{Rte, IsoFlags};
use super::state::VEC_ALLOC;
use super::mmio::{redtbl_read, redtbl_write};
use super::ops_msi::is_gsi_claimed;
use super::ops_helpers::{iso_flags_for, locate};

pub fn alloc_route(gsi: u32, dest_apic_id: u32) -> IoApicResult<(u8, Rte)> {
    if is_gsi_claimed(gsi) {
        return Err(IoApicError::GsiClaimedForMsi);
    }
    let vector = VEC_ALLOC.lock().alloc().ok_or(IoApicError::VectorExhausted)?;
    let mut rte = Rte::fixed(vector, dest_apic_id);
    if let Some(flags) = iso_flags_for(gsi) {
        if flags.contains(IsoFlags::TRIGGER_LEVEL) { rte.level_trigger = true; }
        if flags.contains(IsoFlags::POLARITY_ACTIVE_LOW) { rte.active_low = true; }
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
        if masked { low |= 1 << 16; } else { low &= !(1 << 16); }
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

pub fn free_vector(vec: u8) { VEC_ALLOC.lock().free(vec); }
