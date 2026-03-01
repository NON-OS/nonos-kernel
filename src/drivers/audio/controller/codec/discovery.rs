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

extern crate alloc;

use alloc::vec::Vec;
use crate::drivers::audio::error::AudioError;
use crate::drivers::audio::types::DmaRegion;
use crate::drivers::audio::constants::*;
use super::super::helpers::RegisterAccess;
use super::super::corb_rirb::{corb_send_verb, get_parameter};
use super::constants::*;
use super::quirks::get_codec_quirks;
use super::types::{CodecInfo, WidgetInfo, AudioPath, CodecPaths};
use super::stats::{increment_codecs_discovered, increment_paths_discovered, increment_quirks_applied};

pub(crate) fn discover_codec<T: RegisterAccess>(
    ctrl: &T,
    corb: &DmaRegion,
    rirb: &DmaRegion,
    corb_entries: usize,
    rirb_entries: usize,
    cad: u8,
) -> Result<CodecInfo, AudioError> {
    let vendor_device = get_parameter(
        ctrl, corb, rirb, corb_entries, rirb_entries,
        cad, 0, PARAM_VENDOR_ID,
    )?;

    let vendor_id = (vendor_device >> 16) as u16;
    let device_id = (vendor_device & 0xFFFF) as u16;

    if vendor_id == 0x0000 || vendor_id == 0xFFFF {
        return Err(AudioError::NoCodecPresent);
    }

    let revision_id = get_parameter(
        ctrl, corb, rirb, corb_entries, rirb_entries,
        cad, 0, PARAM_REVISION_ID,
    ).unwrap_or(0);

    let sub_nodes = get_parameter(
        ctrl, corb, rirb, corb_entries, rirb_entries,
        cad, 0, PARAM_SUB_NODE_COUNT,
    ).unwrap_or(0);

    let fn_group_start = ((sub_nodes >> 16) & 0xFF) as u8;
    let fn_group_count = (sub_nodes & 0xFF) as u8;

    let quirks = get_codec_quirks(vendor_id, device_id);

    increment_codecs_discovered();
    if quirks.has_quirks() {
        increment_quirks_applied();
    }

    Ok(CodecInfo {
        cad,
        vendor_id,
        device_id,
        revision_id,
        fn_group_start,
        fn_group_count,
        quirks,
    })
}

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
        ctrl, corb, rirb, corb_entries, rirb_entries,
        cad, nid, PARAM_AUDIO_WIDGET_CAP,
    )?;

    let widget_type = ((caps >> 20) & 0xF) as u8;

    let conn_len = if (caps & (1 << 8)) != 0 {
        let conn_info = get_parameter(
            ctrl, corb, rirb, corb_entries, rirb_entries,
            cad, nid, PARAM_CONN_LIST_LEN,
        ).unwrap_or(0);
        (conn_info & 0x7F) as u8
    } else {
        0
    };

    let conn_first = if conn_len > 0 {
        let conn = corb_send_verb(
            ctrl, corb, rirb, corb_entries, rirb_entries,
            cad, nid, VERB_GET_CONN_LIST, 0,
        ).unwrap_or(0);
        (conn & 0xFF) as u8
    } else {
        0
    };

    let (pin_caps, pin_config) = if widget_type == WIDGET_TYPE_PIN {
        let pc = get_parameter(
            ctrl, corb, rirb, corb_entries, rirb_entries,
            cad, nid, PARAM_PIN_CAP,
        ).unwrap_or(0);
        let cfg = corb_send_verb(
            ctrl, corb, rirb, corb_entries, rirb_entries,
            cad, nid, VERB_GET_CONFIG_DEFAULT, 0,
        ).unwrap_or(0);
        (pc, cfg)
    } else {
        (0, 0)
    };

    let amp_in_caps = if (caps & (1 << 1)) != 0 {
        get_parameter(
            ctrl, corb, rirb, corb_entries, rirb_entries,
            cad, nid, PARAM_AMP_IN_CAP,
        ).unwrap_or(0)
    } else {
        0
    };

    let amp_out_caps = if (caps & (1 << 2)) != 0 {
        get_parameter(
            ctrl, corb, rirb, corb_entries, rirb_entries,
            cad, nid, PARAM_AMP_OUT_CAP,
        ).unwrap_or(0)
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

pub(crate) fn discover_paths<T: RegisterAccess>(
    ctrl: &T,
    corb: &DmaRegion,
    rirb: &DmaRegion,
    corb_entries: usize,
    rirb_entries: usize,
    codec: &CodecInfo,
) -> Result<CodecPaths, AudioError> {
    let mut paths = CodecPaths::default();

    for fg_idx in 0..codec.fn_group_count {
        let fg_nid = codec.fn_group_start + fg_idx;

        let fg_type = get_parameter(
            ctrl, corb, rirb, corb_entries, rirb_entries,
            codec.cad, fg_nid, PARAM_FN_GROUP_TYPE,
        ).unwrap_or(0);

        if (fg_type & 0xFF) != 0x01 {
            continue;
        }

        let sub_nodes = get_parameter(
            ctrl, corb, rirb, corb_entries, rirb_entries,
            codec.cad, fg_nid, PARAM_SUB_NODE_COUNT,
        ).unwrap_or(0);

        let widget_start = ((sub_nodes >> 16) & 0xFF) as u8;
        let widget_count = ((sub_nodes & 0xFF) as u8).min(MAX_WIDGETS as u8);

        let mut widgets: [WidgetInfo; MAX_WIDGETS] = [WidgetInfo::default(); MAX_WIDGETS];
        let mut widget_map: [u8; 256] = [0xFF; 256];

        for w_idx in 0..widget_count {
            let nid = widget_start.saturating_add(w_idx);
            if let Ok(widget) = discover_widget(
                ctrl, corb, rirb, corb_entries, rirb_entries,
                codec.cad, nid,
            ) {
                widgets[w_idx as usize] = widget;
                widget_map[nid as usize] = w_idx;
            }
        }

        for w_idx in 0..widget_count as usize {
            let widget = &widgets[w_idx];

            if !widget.is_output_pin() || !widget.is_connected() {
                continue;
            }

            let dev_type = widget.pin_device_type();
            let priority = match dev_type {
                PIN_DEV_SPEAKER => 0,
                PIN_DEV_HP_OUT => 1,
                PIN_DEV_LINE_OUT => 2,
                _ => 10,
            };

            if priority > 5 {
                continue;
            }

            if let Some(path) = trace_to_dac(
                ctrl, corb, rirb, corb_entries, rirb_entries,
                codec.cad, widget.nid, &widgets, &widget_map, widget_start, widget_count,
            ) {
                if paths.output_count < MAX_OUTPUT_PATHS {
                    let mut audio_path = AudioPath {
                        dac_nid: path.0,
                        path: [0; 8],
                        path_len: path.1.len() as u8,
                        pin_nid: widget.nid,
                        device_type: dev_type,
                        active: false,
                    };
                    for (i, &nid) in path.1.iter().enumerate() {
                        if i < 8 {
                            audio_path.path[i] = nid;
                        }
                    }

                    if priority < match paths.output_paths[paths.primary_output].device_type {
                        PIN_DEV_SPEAKER => 0,
                        PIN_DEV_HP_OUT => 1,
                        PIN_DEV_LINE_OUT => 2,
                        _ => 10,
                    } {
                        paths.primary_output = paths.output_count;
                    }

                    paths.output_paths[paths.output_count] = audio_path;
                    paths.output_count += 1;
                }
            }
        }
    }

    if paths.output_count == 0 {
        return Err(AudioError::CodecInitFailed);
    }

    increment_paths_discovered(paths.output_count as u32);

    Ok(paths)
}

fn trace_to_dac<T: RegisterAccess>(
    ctrl: &T,
    corb: &DmaRegion,
    rirb: &DmaRegion,
    corb_entries: usize,
    rirb_entries: usize,
    cad: u8,
    start_nid: u8,
    widgets: &[WidgetInfo; MAX_WIDGETS],
    widget_map: &[u8; 256],
    widget_start: u8,
    widget_count: u8,
) -> Option<(u8, Vec<u8>)> {
    let mut path: Vec<u8> = Vec::with_capacity(8);
    let mut current_nid = start_nid;
    let mut visited: [bool; 256] = [false; 256];

    for _ in 0..MAX_DEPTH {
        if visited[current_nid as usize] {
            return None;
        }
        visited[current_nid as usize] = true;

        let idx = widget_map[current_nid as usize];
        if idx == 0xFF || idx >= widget_count {
            return None;
        }

        let widget = &widgets[idx as usize];

        if widget.widget_type == WIDGET_TYPE_DAC {
            return Some((current_nid, path));
        }

        if current_nid != start_nid {
            path.push(current_nid);
        }

        if widget.conn_len == 0 {
            return None;
        }

        if widget.widget_type == WIDGET_TYPE_SELECTOR && widget.conn_len > 1 {
            for conn_idx in 0..widget.conn_len.min(16) {
                let conn = corb_send_verb(
                    ctrl, corb, rirb, corb_entries, rirb_entries,
                    cad, current_nid, VERB_GET_CONN_LIST, conn_idx as u16,
                ).unwrap_or(0);
                let next_nid = (conn & 0xFF) as u8;

                if next_nid >= widget_start && next_nid < widget_start + widget_count {
                    let next_idx = widget_map[next_nid as usize];
                    if next_idx != 0xFF && next_idx < widget_count {
                        let next_widget = &widgets[next_idx as usize];
                        if next_widget.widget_type == WIDGET_TYPE_DAC {
                            path.push(current_nid);
                            return Some((next_nid, path));
                        }
                    }
                    current_nid = next_nid;
                    break;
                }
            }
        } else {
            let next_nid = widget.conn_first;
            if next_nid < widget_start || next_nid >= widget_start + widget_count {
                return None;
            }
            current_nid = next_nid;
        }
    }

    None
}
