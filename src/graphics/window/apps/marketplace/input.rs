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

use super::state::*;
use super::apps::{get_apps, app_count};
use super::payment::initiate_payment;
use super::capsule::{create_capsule, launch_capsule, stop_capsule, get_capsule, capsule_count};

pub(crate) fn handle_click(x: u32, y: u32, w: u32, _h: u32, mx: i32, my: i32) -> bool {
    let rx = (mx - x as i32) as u32;
    let ry = (my - y as i32) as u32;
    if ry >= 50 && ry < 70 { return handle_category_click(rx); }
    if ry >= 100 { return handle_grid_click(rx, ry - 100, w); }
    false
}

fn handle_category_click(rx: u32) -> bool {
    let cats = [(20u32, 44, CAT_ALL), (64, 112, CAT_SOCIAL), (132, 188, CAT_BROWSER), (208, 248, CAT_TOOLS)];
    for (start, end, cat) in cats { if rx >= start && rx < end { set_category(cat); return true; } }
    false
}

fn handle_grid_click(rx: u32, ry: u32, w: u32) -> bool {
    let cols = ((w - 40) / 200).max(1) as usize;
    let col = ((rx.saturating_sub(20)) / 200) as usize;
    let row = (ry / 100) as usize;
    let idx = scroll() + row * cols + col;
    let apps = get_apps(category());
    if idx < apps.len() {
        if selected() == idx { return try_install(idx); }
        select(idx);
        return true;
    }
    false
}

fn try_install(idx: usize) -> bool {
    let apps = get_apps(category());
    if idx >= apps.len() { return false; }
    let app = &apps[idx];
    if is_installed(idx) {
        if let Some(cap) = get_capsule(idx) {
            if cap.is_running() {
                if stop_capsule(idx).is_ok() { crate::graphics::window::notify_info(b"Stopped"); }
            } else {
                let token = crate::capabilities::CapabilityToken::empty();
                if launch_capsule(idx, &token).is_ok() { crate::graphics::window::notify_success(b"Launched!"); }
            }
        }
        return true;
    }
    if app.nox_fee == 0 {
        if capsule_count() >= super::capsule::MAX_CAPSULES as u32 {
            crate::graphics::window::notify_info(b"Capsule limit reached");
            return true;
        }
        let id = [0u8; 32];
        let name_str = core::str::from_utf8(&app.name).unwrap_or("app");
        if create_capsule(idx, &id, name_str, 0).is_some() {
            set_installed(idx, true);
            crate::graphics::window::notify_success(b"Installed!");
        }
        return true;
    }
    if initiate_payment(idx, app.nox_fee) { super::payment::execute_pending_payment(); }
    true
}

pub(crate) fn handle_key(ch: u8) {
    let cnt = app_count(category());
    if cnt == 0 { return; }
    let sel = selected();
    match ch {
        b'j' | 40 => if sel + 1 < cnt { select(sel + 1); },
        b'k' | 38 => if sel > 0 { select(sel - 1); },
        13 => { try_install(sel); },
        _ => {}
    }
}

