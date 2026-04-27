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

use super::create_state::*;
use super::state::*;

pub(crate) fn handle_click(rx: u32, ry: u32) -> bool {
    if ry >= 70 && ry < 98 {
        return handle_preset_click(rx);
    }
    if ry >= 180 && ry < 216 {
        set_focus(0);
        return true;
    }
    if ry >= 250 && ry < 286 {
        set_focus(1);
        return true;
    }
    if ry >= 310 && ry < 346 && rx >= 20 && rx < 140 {
        create_agent();
        return true;
    }
    false
}

fn handle_preset_click(rx: u32) -> bool {
    let presets = crate::agents::presets::list_presets();
    let mut px = 20u32;
    for (i, (name, factory)) in presets.iter().enumerate() {
        let len = name.iter().position(|&c| c == 0).unwrap_or(name.len()).min(14);
        let btn_w = len as u32 * 8 + 16;
        if rx >= px && rx < px + btn_w {
            set_preset_idx(i as u8);
            let cfg = factory();
            let id = crate::agents::registry::create_agent(cfg);
            set_selected(id);
            set_view(VIEW_LIST);
            crate::graphics::window::notify_success(b"Agent created from preset!");
            return true;
        }
        px += btn_w + 8;
        if px > 420 {
            break;
        }
    }
    false
}

pub(crate) fn handle_key(ch: u8) {
    if focus() == 0 {
        handle_name_key(ch);
    } else {
        handle_prompt_key(ch);
    }
}

fn handle_name_key(ch: u8) {
    let len = name_len();
    if ch == 8 && len > 0 {
        set_name_len(len - 1);
    } else if ch >= 32 && ch < 127 && len < 31 {
        unsafe {
            NAME_BUF[len] = ch;
        }
        set_name_len(len + 1);
    }
}

fn handle_prompt_key(ch: u8) {
    let len = prompt_len();
    if ch == 8 && len > 0 {
        set_prompt_len(len - 1);
    } else if ch >= 32 && ch < 127 && len < 255 {
        unsafe {
            PROMPT_BUF[len] = ch;
        }
        set_prompt_len(len + 1);
    }
}

fn create_agent() {
    let nl = name_len();
    if nl == 0 {
        crate::graphics::window::notify_error(b"Enter agent name");
        return;
    }
    let mut config = crate::agents::core::AgentConfig::default();
    unsafe {
        config.name[..nl].copy_from_slice(&NAME_BUF[..nl]);
        config.system_prompt = PROMPT_BUF[..prompt_len()].to_vec();
    }
    let id = crate::agents::registry::create_agent(config);
    set_name_len(0);
    set_prompt_len(0);
    set_selected(id);
    set_view(VIEW_LIST);
    crate::graphics::window::notify_success(b"Agent created!");
}
