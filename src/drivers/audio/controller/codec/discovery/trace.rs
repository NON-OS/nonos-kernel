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
use super::super::super::corb_rirb::corb_send_verb;
use super::super::super::helpers::RegisterAccess;
use super::super::constants::*;
use super::super::types::WidgetInfo;
use crate::drivers::audio::constants::*;
use crate::drivers::audio::types::DmaRegion;
use alloc::vec::Vec;

pub(super) fn trace_to_dac<T: RegisterAccess>(
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
                    ctrl,
                    corb,
                    rirb,
                    corb_entries,
                    rirb_entries,
                    cad,
                    current_nid,
                    VERB_GET_CONN_LIST,
                    conn_idx as u16,
                )
                .unwrap_or(0);
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
