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

//! CORB/RIRB command ring buffer and immediate command interface.

use core::ptr;
use core::sync::atomic::Ordering;

use super::super::error::AudioError;
use super::super::types::DmaRegion;
use super::super::constants::*;
use super::helpers::{RegisterAccess, spin_until, spin_while};

#[inline]
pub const fn compose_verb(cad: u8, nid: u8, verb: u16, payload: u16) -> u32 {
    debug_assert!(cad <= 15, "Codec address must be 0-15");
    debug_assert!(nid <= 127, "Node ID must be 0-127");

    ((cad as u32 & 0xF) << 28)
        | ((nid as u32 & 0x7F) << 20)
        | ((verb as u32 & 0xFFF) << 8)
        | (payload as u32 & 0xFF)
}

#[inline]
pub(super) const fn decompose_response(response: u64) -> (u32, u8, u8) {
    let data = (response & 0xFFFF_FFFF) as u32;
    let ext = (response >> 32) as u32;
    let cad = ((ext >> 4) & 0xF) as u8;
    let unsol = (ext & 0xF) as u8;
    (data, cad, unsol)
}

pub(super) fn corb_send_verb<T: RegisterAccess>(
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
    if cad > 15 {
        return Err(AudioError::InvalidCodecAddress);
    }
    if nid > 127 {
        return Err(AudioError::InvalidNodeId);
    }

    let cmd = compose_verb(cad, nid, verb, payload);

    if let Some(response) = try_corb_send(ctrl, corb, rirb, corb_entries, rirb_entries, cmd) {
        return Ok(response);
    }

    immediate_cmd(ctrl, cad, nid, verb, payload)
}

fn try_corb_send<T: RegisterAccess>(
    ctrl: &T,
    corb: &DmaRegion,
    rirb: &DmaRegion,
    corb_entries: usize,
    rirb_entries: usize,
    cmd: u32,
) -> Option<u32> {
    // SAFETY: CORB is valid DMA region, writing within bounds (wp < corb_entries)
    unsafe {
        let wp = ctrl.read_reg16(CORBWP) as usize;
        let next_wp = (wp + 1) % corb_entries;

        let ptr_corb = corb.as_mut_ptr::<u32>().add(next_wp);
        ptr::write_volatile(ptr_corb, cmd);

        core::sync::atomic::fence(Ordering::SeqCst);

        ctrl.write_reg16(CORBWP, next_wp as u16);
    }

    let mut spins = SPIN_TIMEOUT_DEFAULT;
    while spins > 0 {
        // SAFETY: reading RIRB status and write pointer registers
        unsafe {
            let sts = ctrl.read_reg8(RIRBSTS);
            if (sts & RIRBSTS_RIRBOIS) != 0 {
                ctrl.write_reg8(RIRBSTS, RIRBSTS_RIRBOIS);
            }

            if (sts & RIRBSTS_RINTFL) != 0 {
                ctrl.write_reg8(RIRBSTS, RIRBSTS_RINTFL);

                let wp = ctrl.read_reg16(RIRBWP) as usize;
                if wp != 0 {
                    let rp = wp % rirb_entries;
                    let base = rirb.as_ptr::<u64>();
                    let resp = ptr::read_volatile(base.add(rp));
                    let (resp_data, _cad, _unsol) = decompose_response(resp);

                    return Some(resp_data);
                }
            }
        }
        core::hint::spin_loop();
        spins -= 1;
    }

    None
}

pub(super) fn immediate_cmd<T: RegisterAccess>(
    ctrl: &T,
    cad: u8,
    nid: u8,
    verb: u16,
    payload: u16,
) -> Result<u32, AudioError> {
    if cad > 15 {
        return Err(AudioError::InvalidCodecAddress);
    }
    if nid > 127 {
        return Err(AudioError::InvalidNodeId);
    }

    let cmd = compose_verb(cad, nid, verb, payload);

    if !spin_while(|| (ctrl.read_reg8(IRS) & IRS_BUSY) != 0, SPIN_TIMEOUT_SHORT) {
        return Err(AudioError::ImmediateCmdBusy);
    }

    ctrl.write_reg8(IRS, IRS_VALID);
    ctrl.write_reg32(IC, cmd);

    if !spin_until(|| (ctrl.read_reg8(IRS) & IRS_VALID) != 0, SPIN_TIMEOUT_DEFAULT) {
        return Err(AudioError::ImmediateResponseTimeout);
    }

    let resp = ctrl.read_reg32(IR);
    Ok(resp)
}

pub(super) fn init_corb<T: RegisterAccess>(ctrl: &T, corb: &DmaRegion) {
    debug_assert!(corb.len() >= CORB_SIZE, "CORB must be at least 1024 bytes");
    debug_assert!(corb.phys() % DMA_ALIGNMENT as u64 == 0, "CORB must be 128-byte aligned");

    ctrl.write_reg8(CORBCTL, 0);
    spin_while(|| (ctrl.read_reg8(CORBCTL) & CORBCTL_CORBRUN) != 0, SPIN_TIMEOUT_SHORT);

    ctrl.write_reg32(CORBLBASE, (corb.phys() & 0xFFFF_FFFF) as u32);
    ctrl.write_reg32(CORBUBASE, (corb.phys() >> 32) as u32);

    ctrl.write_reg8(CORBSIZE, CORB_RIRB_SIZE_256);
    ctrl.write_reg16(CORBWP, 0);
    ctrl.write_reg16(CORBRP, CORBRP_RST);

    spin_until(|| (ctrl.read_reg16(CORBRP) & CORBRP_RST) != 0, SPIN_TIMEOUT_SHORT);

    ctrl.write_reg16(CORBRP, 0);

    spin_while(|| (ctrl.read_reg16(CORBRP) & CORBRP_RST) != 0, SPIN_TIMEOUT_SHORT);

    ctrl.write_reg8(CORBCTL, CORBCTL_CORBRUN | CORBCTL_CMEIE);
    ctrl.write_reg8(CORBSTS, CORBSTS_CMEI);
}

pub(super) fn init_rirb<T: RegisterAccess>(ctrl: &T, rirb: &DmaRegion) {
    debug_assert!(rirb.len() >= RIRB_SIZE, "RIRB must be at least 2048 bytes");
    debug_assert!(rirb.phys() % DMA_ALIGNMENT as u64 == 0, "RIRB must be 128-byte aligned");

    ctrl.write_reg8(RIRBCTL, 0);
    spin_while(|| (ctrl.read_reg8(RIRBCTL) & RIRBCTL_RIRBDMAEN) != 0, SPIN_TIMEOUT_SHORT);

    ctrl.write_reg32(RIRBLBASE, (rirb.phys() & 0xFFFF_FFFF) as u32);
    ctrl.write_reg32(RIRBUBASE, (rirb.phys() >> 32) as u32);

    ctrl.write_reg8(RIRBSIZE, CORB_RIRB_SIZE_256);
    ctrl.write_reg16(RIRBWP, 1 << 15);

    spin_while(|| (ctrl.read_reg16(RIRBWP) & (1 << 15)) != 0, SPIN_TIMEOUT_SHORT);

    ctrl.write_reg16(RINTCNT, 1);
    ctrl.write_reg8(RIRBCTL, RIRBCTL_RIRBDMAEN | RIRBCTL_RINTCTL | RIRBCTL_RIRBOIC);
    ctrl.write_reg8(RIRBSTS, RIRBSTS_RIRBOIS | RIRBSTS_RINTFL);
}

pub(super) fn stop_corb<T: RegisterAccess>(ctrl: &T) {
    ctrl.write_reg8(CORBCTL, 0);
    spin_while(|| (ctrl.read_reg8(CORBCTL) & CORBCTL_CORBRUN) != 0, SPIN_TIMEOUT_SHORT);
}

pub(super) fn stop_rirb<T: RegisterAccess>(ctrl: &T) {
    ctrl.write_reg8(RIRBCTL, 0);
    spin_while(|| (ctrl.read_reg8(RIRBCTL) & RIRBCTL_RIRBDMAEN) != 0, SPIN_TIMEOUT_SHORT);
}

pub(super) fn get_parameter<T: RegisterAccess>(
    ctrl: &T,
    corb: &DmaRegion,
    rirb: &DmaRegion,
    corb_entries: usize,
    rirb_entries: usize,
    cad: u8,
    nid: u8,
    param: u16,
) -> Result<u32, AudioError> {
    corb_send_verb(
        ctrl, corb, rirb, corb_entries, rirb_entries,
        cad, nid, VERB_GET_PARAMETER, param,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compose_verb() {
        let verb = compose_verb(0, 0, 0xF00, 0x00);
        assert_eq!(verb, 0x000F_0000);

        let verb = compose_verb(1, 2, 0x705, 0x00);
        assert_eq!(verb, 0x1027_0500);
    }

    #[test]
    fn test_decompose_response() {
        let response = 0x0000_0020_1234_5678u64;
        let (data, cad, unsol) = decompose_response(response);
        assert_eq!(data, 0x12345678);
        assert_eq!(cad, 2);
        assert_eq!(unsol, 0);
    }
}
