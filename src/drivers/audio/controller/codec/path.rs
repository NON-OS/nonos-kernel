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
use crate::drivers::audio::constants::{
    VERB_SET_STREAM_CHANNEL, VERB_GET_CONN_LIST, VERB_SET_CONN_SELECT,
    PARAM_AUDIO_WIDGET_CAP, PARAM_PIN_CAP, PARAM_CONN_LIST_LEN,
};
use super::super::helpers::RegisterAccess;
use super::super::corb_rirb::{corb_send_verb, get_parameter};
use super::constants::*;
use super::types::{CodecInfo, AudioPath, CodecPaths};
use super::control::{set_power_state, set_pin_control, set_eapd, set_amp_gain};
use super::discovery::discover_paths;

pub(crate) fn init_codec_path<T: RegisterAccess>(
    ctrl: &T,
    corb: &DmaRegion,
    rirb: &DmaRegion,
    corb_entries: usize,
    rirb_entries: usize,
    codec: &CodecInfo,
) -> Result<CodecPaths, AudioError> {
    for fg_idx in 0..codec.fn_group_count {
        let fg_nid = codec.fn_group_start + fg_idx;
        let _ = set_power_state(
            ctrl, corb, rirb, corb_entries, rirb_entries,
            codec.cad, fg_nid, POWER_STATE_D0,
        );
    }

    let mut paths = discover_paths(
        ctrl, corb, rirb, corb_entries, rirb_entries, codec,
    )?;

    if paths.output_count > 0 {
        let path = &mut paths.output_paths[paths.primary_output];
        configure_output_path(
            ctrl, corb, rirb, corb_entries, rirb_entries,
            codec.cad, path,
        )?;
        path.active = true;
    }

    Ok(paths)
}

fn configure_output_path<T: RegisterAccess>(
    ctrl: &T,
    corb: &DmaRegion,
    rirb: &DmaRegion,
    corb_entries: usize,
    rirb_entries: usize,
    cad: u8,
    path: &AudioPath,
) -> Result<(), AudioError> {
    set_power_state(
        ctrl, corb, rirb, corb_entries, rirb_entries,
        cad, path.dac_nid, POWER_STATE_D0,
    )?;

    corb_send_verb(
        ctrl, corb, rirb, corb_entries, rirb_entries,
        cad, path.dac_nid, VERB_SET_STREAM_CHANNEL, 0x10,
    )?;

    for i in 0..path.path_len as usize {
        let nid = path.path[i];
        if nid == 0 {
            continue;
        }

        let _ = set_power_state(
            ctrl, corb, rirb, corb_entries, rirb_entries,
            cad, nid, POWER_STATE_D0,
        );

        let caps = get_parameter(
            ctrl, corb, rirb, corb_entries, rirb_entries,
            cad, nid, PARAM_AUDIO_WIDGET_CAP,
        ).unwrap_or(0);
        let widget_type = ((caps >> 20) & 0xF) as u8;

        if (caps & (1 << 2)) != 0 {
            set_amp_gain(
                ctrl, corb, rirb, corb_entries, rirb_entries,
                cad, nid, true, false, 0, 0x7F,
            )?;
        }
        if (caps & (1 << 1)) != 0 {
            set_amp_gain(
                ctrl, corb, rirb, corb_entries, rirb_entries,
                cad, nid, false, false, 0, 0x7F,
            )?;
        }

        if widget_type == WIDGET_TYPE_SELECTOR {
            let next_nid = if i + 1 < path.path_len as usize {
                path.path[i + 1]
            } else {
                path.dac_nid
            };

            let conn_len = get_parameter(
                ctrl, corb, rirb, corb_entries, rirb_entries,
                cad, nid, PARAM_CONN_LIST_LEN,
            ).unwrap_or(0) & 0x7F;

            let mut selected_index: u16 = 0;
            for conn_idx in 0..conn_len.min(16) {
                let conn = corb_send_verb(
                    ctrl, corb, rirb, corb_entries, rirb_entries,
                    cad, nid, VERB_GET_CONN_LIST, conn_idx as u16,
                ).unwrap_or(0);
                if (conn & 0xFF) as u8 == next_nid {
                    selected_index = conn_idx as u16;
                    break;
                }
            }

            corb_send_verb(
                ctrl, corb, rirb, corb_entries, rirb_entries,
                cad, nid, VERB_SET_CONN_SELECT, selected_index,
            )?;
        }
    }

    set_power_state(
        ctrl, corb, rirb, corb_entries, rirb_entries,
        cad, path.pin_nid, POWER_STATE_D0,
    )?;

    let pin_caps = get_parameter(
        ctrl, corb, rirb, corb_entries, rirb_entries,
        cad, path.pin_nid, PARAM_PIN_CAP,
    ).unwrap_or(0);

    let mut pin_ctl = PIN_CTL_OUT_EN;
    if path.device_type == PIN_DEV_HP_OUT {
        pin_ctl |= PIN_CTL_HP_EN;
    }
    set_pin_control(
        ctrl, corb, rirb, corb_entries, rirb_entries,
        cad, path.pin_nid, pin_ctl,
    )?;

    if (pin_caps & (1 << 16)) != 0 {
        set_eapd(
            ctrl, corb, rirb, corb_entries, rirb_entries,
            cad, path.pin_nid, EAPD_ENABLE,
        )?;
    }

    let caps = get_parameter(
        ctrl, corb, rirb, corb_entries, rirb_entries,
        cad, path.pin_nid, PARAM_AUDIO_WIDGET_CAP,
    ).unwrap_or(0);
    if (caps & (1 << 2)) != 0 {
        set_amp_gain(
            ctrl, corb, rirb, corb_entries, rirb_entries,
            cad, path.pin_nid, true, false, 0, 0x7F,
        )?;
    }

    Ok(())
}

pub(crate) fn apply_codec_quirks<T: RegisterAccess>(
    ctrl: &T,
    corb: &DmaRegion,
    rirb: &DmaRegion,
    corb_entries: usize,
    rirb_entries: usize,
    codec: &CodecInfo,
) -> Result<(), AudioError> {
    let quirks = &codec.quirks;

    if quirks.gpio_setup {
        setup_gpio(
            ctrl, corb, rirb, corb_entries, rirb_entries,
            codec.cad, codec.fn_group_start, quirks.gpio_mask, quirks.gpio_data,
        )?;
    }

    if quirks.needs_reset {
        reset_codec(ctrl, corb, rirb, corb_entries, rirb_entries, codec.cad)?;
    }

    Ok(())
}

fn setup_gpio<T: RegisterAccess>(
    ctrl: &T,
    corb: &DmaRegion,
    rirb: &DmaRegion,
    corb_entries: usize,
    rirb_entries: usize,
    cad: u8,
    afg_nid: u8,
    mask: u8,
    data: u8,
) -> Result<(), AudioError> {
    let gpio_count = get_parameter(
        ctrl, corb, rirb, corb_entries, rirb_entries,
        cad, afg_nid, PARAM_GPIO_COUNT,
    ).unwrap_or(0);

    let num_gpios = (gpio_count & 0xFF) as u8;
    if num_gpios == 0 {
        return Ok(());
    }

    corb_send_verb(
        ctrl, corb, rirb, corb_entries, rirb_entries,
        cad, afg_nid, VERB_SET_GPIO_MASK, mask as u16,
    )?;

    corb_send_verb(
        ctrl, corb, rirb, corb_entries, rirb_entries,
        cad, afg_nid, VERB_SET_GPIO_DIRECTION, mask as u16,
    )?;

    corb_send_verb(
        ctrl, corb, rirb, corb_entries, rirb_entries,
        cad, afg_nid, VERB_SET_GPIO_DATA, data as u16,
    )?;

    Ok(())
}

fn reset_codec<T: RegisterAccess>(
    ctrl: &T,
    corb: &DmaRegion,
    rirb: &DmaRegion,
    corb_entries: usize,
    rirb_entries: usize,
    cad: u8,
) -> Result<(), AudioError> {
    corb_send_verb(
        ctrl, corb, rirb, corb_entries, rirb_entries,
        cad, 0, 0x7FF, 0,
    )?;

    for _ in 0..1000 {
        core::hint::spin_loop();
    }

    Ok(())
}
