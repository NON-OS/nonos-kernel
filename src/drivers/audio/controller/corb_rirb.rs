// NØNOS Operating System
// Copyright (C) 2025 NØNOS Contributors
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
//!
//! CORB/RIRB command ring buffer and immediate command interface.

use core::ptr;

use super::super::error::AudioError;
use super::super::types::DmaRegion;
use super::super::constants::*;
use super::helpers::{RegisterAccess, spin_until, spin_while};

/// Composes a 32-bit codec verb from components.
///
/// # Verb Format (Section 7.1)
/// - Bits 31:28: Codec Address (CAD)
/// - Bits 27:20: Node ID (NID)
/// - Bits 19:8: Verb ID
/// - Bits 7:0: Payload

#[inline]
pub const fn compose_verb(cad: u8, nid: u8, verb: u16, payload: u16) -> u32 {
    ((cad as u32) << 28) | ((nid as u32) << 20) | ((verb as u32) << 8) | (payload as u32)
}

/// Sends a verb via the CORB and waits for response via RIRB.
pub fn corb_send_verb<T: RegisterAccess>(
    ctrl: &T,
    corb: &DmaRegion,
    rirb: &DmaRegion,
    corb_entries: usize,
    rirb_entries: usize,
    cad: u8,
    nid: u8,
    verb: u16,
    payload: u16,
) -> Result<u32, AudioError> {
    let cmd = compose_verb(cad, nid, verb, payload);

    // Write command to CORB at next write pointer position
    // SAFETY: CORB is a valid DMA region allocated for this purpose.
    // We're writing within bounds (wp < corb_entries).
    unsafe {
        let mut wp = ctrl.read_reg16(CORBWP) as usize;
        wp = (wp + 1) % corb_entries;

        let ptr_corb = corb.as_mut_ptr::<u32>().add(wp);
        ptr::write_volatile(ptr_corb, cmd);

        // Update write pointer to trigger DMA
        ctrl.write_reg16(CORBWP, wp as u16);
    }

    // Wait for RIRB response
    let mut spins = SPIN_TIMEOUT_DEFAULT;
    while spins > 0 {
        // SAFETY: Reading RIRB status and write pointer registers.
        unsafe {
            // Clear overrun status if set
            let sts = ctrl.read_reg8(RIRBSTS);
            if (sts & RIRBSTS_RIRBOIS) != 0 {
                ctrl.write_reg8(RIRBSTS, RIRBSTS_RIRBOIS);
            }

            // Check for new response
            let wp = ctrl.read_reg16(RIRBWP) as usize;
            if wp != 0 {
                let rp = wp % rirb_entries;
                let base = rirb.as_ptr::<u64>();
                let resp = ptr::read_volatile(base.add(rp));
                let resp_lo = (resp & 0xFFFF_FFFF) as u32;

                // Clear RIRBWP by writing it back (per spec)
                ctrl.write_reg16(RIRBWP, wp as u16);

                return Ok(resp_lo);
            }
        }
        core::hint::spin_loop();
        spins -= 1;
    }

    // Fallback to immediate command interface
    immediate_cmd(ctrl, cad, nid, verb, payload)
}

/// Sends a verb via the immediate command interface.
pub fn immediate_cmd<T: RegisterAccess>(
    ctrl: &T,
    cad: u8,
    nid: u8,
    verb: u16,
    payload: u16,
) -> Result<u32, AudioError> {
    let cmd = compose_verb(cad, nid, verb, payload);

    // Wait for not busy
    if !spin_while(|| (ctrl.read_reg8(IRS) & IRS_BUSY) != 0, SPIN_TIMEOUT_SHORT) {
        return Err(AudioError::ImmediateCmdBusy);
    }

    // Write command
    ctrl.write_reg32(IC, cmd);

    // Wait for valid response
    if !spin_until(|| (ctrl.read_reg8(IRS) & IRS_VALID) != 0, SPIN_TIMEOUT_DEFAULT) {
        return Err(AudioError::ImmediateResponseTimeout);
    }

    // Read response
    let resp = ctrl.read_reg32(IR);
    Ok(resp)
}

/// Initializes the CORB (Command Output Ring Buffer).
pub fn init_corb<T: RegisterAccess>(ctrl: &T, corb: &DmaRegion) {
    // Program CORB base address (64-bit split into low/high)
    ctrl.write_reg32(CORBLBASE, (corb.phys() & 0xFFFF_FFFF) as u32);
    ctrl.write_reg32(CORBUBASE, (corb.phys() >> 32) as u32);

    // Set CORB size: 256 entries = 0x02
    ctrl.write_reg8(CORBSIZE, 0x02);

    // Reset write pointer
    ctrl.write_reg16(CORBWP, 0);

    // Reset read pointer (set bit 15, then clear)
    ctrl.write_reg16(CORBRP, 1 << 15);
    ctrl.write_reg16(CORBRP, 0);

    // Enable CORB DMA engine
    ctrl.write_reg8(CORBCTL, CORBCTL_CORBRUN);

    // Clear status
    ctrl.write_reg8(CORBSTS, CORBSTS_CMEI);
}

/// Initializes the RIRB (Response Input Ring Buffer).
pub fn init_rirb<T: RegisterAccess>(ctrl: &T, rirb: &DmaRegion) {
    // Program RIRB base address
    ctrl.write_reg32(RIRBLBASE, (rirb.phys() & 0xFFFF_FFFF) as u32);
    ctrl.write_reg32(RIRBUBASE, (rirb.phys() >> 32) as u32);

    // Set RIRB size: 256 entries = 0x02
    ctrl.write_reg8(RIRBSIZE, 0x02);

    // Reset write pointer (set bit 15, then clear)
    ctrl.write_reg16(RIRBWP, 1 << 15);
    ctrl.write_reg16(RIRBWP, 0);

    // Set interrupt count to 1 (interrupt after each response)
    ctrl.write_reg16(RINTCNT, 1);

    // Enable RIRB DMA + response interrupt
    ctrl.write_reg8(RIRBCTL, RIRBCTL_RIRBDMAEN | RIRBCTL_RINTCTL);

    // Clear status
    ctrl.write_reg8(RIRBSTS, RIRBSTS_RIRBOIS | RIRBSTS_RINTFL);
}

pub fn get_parameter<T: RegisterAccess>(
    ctrl: &T,
    corb: &DmaRegion,
    rirb: &DmaRegion,
    corb_entries: usize,
    rirb_entries: usize,
    cad: u8,
    nid: u8,
    param: u16,
) -> Result<u32, AudioError> {
    corb_send_verb(ctrl, corb, rirb, corb_entries, rirb_entries, cad, nid, VERB_GET_PARAMETER, param)
}
