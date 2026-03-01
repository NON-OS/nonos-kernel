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

use crate::drivers::audio::error::AudioError;
use crate::drivers::audio::types::DmaRegion;
use crate::drivers::audio::constants::*;
use super::super::helpers::RegisterAccess;
use super::super::corb_rirb::corb_send_verb;
use super::types::CodecPaths;

pub(super) fn set_power_state<T: RegisterAccess>(
    ctrl: &T,
    corb: &DmaRegion,
    rirb: &DmaRegion,
    corb_entries: usize,
    rirb_entries: usize,
    cad: u8,
    nid: u8,
    state: u8,
) -> Result<u32, AudioError> {
    corb_send_verb(
        ctrl, corb, rirb, corb_entries, rirb_entries,
        cad, nid, VERB_SET_POWER_STATE, state as u16,
    )
}

pub(super) fn set_pin_control<T: RegisterAccess>(
    ctrl: &T,
    corb: &DmaRegion,
    rirb: &DmaRegion,
    corb_entries: usize,
    rirb_entries: usize,
    cad: u8,
    nid: u8,
    control: u8,
) -> Result<u32, AudioError> {
    corb_send_verb(
        ctrl, corb, rirb, corb_entries, rirb_entries,
        cad, nid, VERB_SET_PIN_WIDGET_CONTROL, control as u16,
    )
}

pub(super) fn set_eapd<T: RegisterAccess>(
    ctrl: &T,
    corb: &DmaRegion,
    rirb: &DmaRegion,
    corb_entries: usize,
    rirb_entries: usize,
    cad: u8,
    nid: u8,
    enable: u8,
) -> Result<u32, AudioError> {
    corb_send_verb(
        ctrl, corb, rirb, corb_entries, rirb_entries,
        cad, nid, VERB_SET_EAPD_BTL_ENABLE, enable as u16,
    )
}

pub(super) fn set_amp_gain<T: RegisterAccess>(
    ctrl: &T,
    corb: &DmaRegion,
    rirb: &DmaRegion,
    corb_entries: usize,
    rirb_entries: usize,
    cad: u8,
    nid: u8,
    output: bool,
    mute: bool,
    index: u8,
    gain: u8,
) -> Result<u32, AudioError> {
    let mut payload: u16 = 0;
    payload |= if output { 1 << 15 } else { 1 << 14 };
    payload |= (1 << 13) | (1 << 12);
    payload |= (index as u16 & 0xF) << 8;
    payload |= if mute { 1 << 7 } else { 0 };
    payload |= (gain as u16) & 0x7F;

    corb_send_verb(
        ctrl, corb, rirb, corb_entries, rirb_entries,
        cad, nid, VERB_SET_AMP_GAIN_MUTE, payload,
    )
}

pub(crate) fn set_volume<T: RegisterAccess>(
    ctrl: &T,
    corb: &DmaRegion,
    rirb: &DmaRegion,
    corb_entries: usize,
    rirb_entries: usize,
    cad: u8,
    paths: &CodecPaths,
    volume: u8,
) -> Result<(), AudioError> {
    if paths.output_count == 0 {
        return Err(AudioError::StreamNotConfigured);
    }

    let path = &paths.output_paths[paths.primary_output];
    let gain = ((volume as u16 * 127) / 100) as u8;
    let mute = volume == 0;

    set_amp_gain(
        ctrl, corb, rirb, corb_entries, rirb_entries,
        cad, path.dac_nid, true, mute, 0, gain,
    )?;

    set_amp_gain(
        ctrl, corb, rirb, corb_entries, rirb_entries,
        cad, path.pin_nid, true, mute, 0, gain,
    )?;

    Ok(())
}

pub(crate) fn set_mute<T: RegisterAccess>(
    ctrl: &T,
    corb: &DmaRegion,
    rirb: &DmaRegion,
    corb_entries: usize,
    rirb_entries: usize,
    cad: u8,
    paths: &CodecPaths,
    mute: bool,
) -> Result<(), AudioError> {
    if paths.output_count == 0 {
        return Err(AudioError::StreamNotConfigured);
    }

    let path = &paths.output_paths[paths.primary_output];
    let gain = if mute { 0 } else { 0x7F };

    set_amp_gain(
        ctrl, corb, rirb, corb_entries, rirb_entries,
        cad, path.dac_nid, true, mute, 0, gain,
    )?;

    set_amp_gain(
        ctrl, corb, rirb, corb_entries, rirb_entries,
        cad, path.pin_nid, true, mute, 0, gain,
    )?;

    Ok(())
}
