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

use super::super::super::corb_rirb::get_parameter;
use super::super::super::helpers::RegisterAccess;
use super::super::constants::*;
use super::super::stats::increment_paths_discovered;
use super::super::types::{AudioPath, CodecInfo, CodecPaths, WidgetInfo};
use super::trace::trace_to_dac;
use super::widget::discover_widget;
use crate::drivers::audio::constants::*;
use crate::drivers::audio::error::AudioError;
use crate::drivers::audio::types::DmaRegion;

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
            ctrl,
            corb,
            rirb,
            corb_entries,
            rirb_entries,
            codec.cad,
            fg_nid,
            PARAM_FN_GROUP_TYPE,
        )
        .unwrap_or(0);
        if (fg_type & 0xFF) != 0x01 {
            continue;
        }
        let sub_nodes = get_parameter(
            ctrl,
            corb,
            rirb,
            corb_entries,
            rirb_entries,
            codec.cad,
            fg_nid,
            PARAM_SUB_NODE_COUNT,
        )
        .unwrap_or(0);
        let widget_start = ((sub_nodes >> 16) & 0xFF) as u8;
        let widget_count = ((sub_nodes & 0xFF) as u8).min(MAX_WIDGETS as u8);
        let mut widgets: [WidgetInfo; MAX_WIDGETS] = [WidgetInfo::default(); MAX_WIDGETS];
        let mut widget_map: [u8; 256] = [0xFF; 256];
        for w_idx in 0..widget_count {
            let nid = widget_start.saturating_add(w_idx);
            if let Ok(widget) =
                discover_widget(ctrl, corb, rirb, corb_entries, rirb_entries, codec.cad, nid)
            {
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
                ctrl,
                corb,
                rirb,
                corb_entries,
                rirb_entries,
                codec.cad,
                widget.nid,
                &widgets,
                &widget_map,
                widget_start,
                widget_count,
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
                    if priority
                        < match paths.output_paths[paths.primary_output].device_type {
                            PIN_DEV_SPEAKER => 0,
                            PIN_DEV_HP_OUT => 1,
                            PIN_DEV_LINE_OUT => 2,
                            _ => 10,
                        }
                    {
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
