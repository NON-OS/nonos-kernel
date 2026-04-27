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

use super::super::super::corb_rirb::{corb_send_verb, get_parameter};
use super::super::super::helpers::RegisterAccess;
use super::super::constants::*;
use super::super::types::WidgetInfo;
use crate::drivers::audio::constants::*;
use crate::drivers::audio::error::AudioError;
use crate::drivers::audio::types::DmaRegion;

pub(super) fn discover_widget<T: RegisterAccess>(
    ctrl: &T,
    corb: &DmaRegion,
    rirb: &DmaRegion,
    corb_entries: usize,
    rirb_entries: usize,
    cad: u8,
    nid: u8,
) -> Result<WidgetInfo, AudioError> {
    let caps = get_parameter(
        ctrl,
        corb,
        rirb,
        corb_entries,
        rirb_entries,
        cad,
        nid,
        PARAM_AUDIO_WIDGET_CAP,
    )?;
    let widget_type = ((caps >> 20) & 0xF) as u8;
    let conn_len = if (caps & (1 << 8)) != 0 {
        let conn_info = get_parameter(
            ctrl,
            corb,
            rirb,
            corb_entries,
            rirb_entries,
            cad,
            nid,
            PARAM_CONN_LIST_LEN,
        )
        .unwrap_or(0);
        (conn_info & 0x7F) as u8
    } else {
        0
    };
    let conn_first = if conn_len > 0 {
        let conn = corb_send_verb(
            ctrl,
            corb,
            rirb,
            corb_entries,
            rirb_entries,
            cad,
            nid,
            VERB_GET_CONN_LIST,
            0,
        )
        .unwrap_or(0);
        (conn & 0xFF) as u8
    } else {
        0
    };
    let (pin_caps, pin_config) = if widget_type == WIDGET_TYPE_PIN {
        let pc =
            get_parameter(ctrl, corb, rirb, corb_entries, rirb_entries, cad, nid, PARAM_PIN_CAP)
                .unwrap_or(0);
        let cfg = corb_send_verb(
            ctrl,
            corb,
            rirb,
            corb_entries,
            rirb_entries,
            cad,
            nid,
            VERB_GET_CONFIG_DEFAULT,
            0,
        )
        .unwrap_or(0);
        (pc, cfg)
    } else {
        (0, 0)
    };
    let amp_in_caps = if (caps & (1 << 1)) != 0 {
        get_parameter(ctrl, corb, rirb, corb_entries, rirb_entries, cad, nid, PARAM_AMP_IN_CAP)
            .unwrap_or(0)
    } else {
        0
    };
    let amp_out_caps = if (caps & (1 << 2)) != 0 {
        get_parameter(ctrl, corb, rirb, corb_entries, rirb_entries, cad, nid, PARAM_AMP_OUT_CAP)
            .unwrap_or(0)
    } else {
        0
    };
    Ok(WidgetInfo {
        nid,
        widget_type,
        caps,
        conn_len,
        conn_first,
        pin_caps,
        pin_config,
        amp_in_caps,
        amp_out_caps,
    })
}
