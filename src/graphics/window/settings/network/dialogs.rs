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

use core::sync::atomic::Ordering;
use crate::graphics::framebuffer::{fill_rect, COLOR_ACCENT, COLOR_TEXT_WHITE, COLOR_GREEN};
use crate::graphics::window::settings::render::draw_string;

use super::state::*;

pub fn draw_password_dialog(base_x: u32, base_y: u32, base_w: u32) {
    let dialog_w = 320u32;
    let dialog_h = 160u32;
    let dialog_x = base_x + (base_w - dialog_w) / 2;
    let dialog_y = base_y + 80;

    fill_rect(dialog_x, dialog_y, dialog_w, dialog_h, 0xFF1A1F26);
    fill_rect(
        dialog_x + 1,
        dialog_y + 1,
        dialog_w - 2,
        dialog_h - 2,
        0xFF0D1117,
    );

    draw_string(
        dialog_x + 15,
        dialog_y + 12,
        b"Enter WiFi Password",
        COLOR_TEXT_WHITE,
    );

    let results = CACHED_SCAN_RESULTS.lock();
    let selected = SELECTED_NETWORK.load(Ordering::Relaxed) as usize;
    if let Some(network) = results.get(selected) {
        draw_string(dialog_x + 15, dialog_y + 32, b"Network:", 0xFF7D8590);
        draw_string(
            dialog_x + 80,
            dialog_y + 32,
            network.ssid.as_bytes(),
            COLOR_ACCENT,
        );
    }
    drop(results);

    fill_rect(dialog_x + 15, dialog_y + 55, dialog_w - 30, 30, 0xFF2D333B);
    let pwd_len = PASSWORD_LEN.load(Ordering::Relaxed) as usize;
    let dots: [u8; 32] = [b'*'; 32];
    let display_len = pwd_len.min(32);
    draw_string(
        dialog_x + 22,
        dialog_y + 62,
        &dots[..display_len],
        COLOR_TEXT_WHITE,
    );

    let cursor_x = dialog_x + 22 + (display_len as u32) * 8;
    if (crate::sys::clock::unix_ms() / 500) % 2 == 0 {
        fill_rect(cursor_x, dialog_y + 60, 2, 18, COLOR_ACCENT);
    }

    fill_rect(dialog_x + 15, dialog_y + 100, 90, 32, 0xFF2D333B);
    draw_string(dialog_x + 35, dialog_y + 108, b"Cancel", COLOR_TEXT_WHITE);

    let connecting = CONNECTING.load(Ordering::Relaxed);
    let connect_color = if connecting { 0xFF2D333B } else { COLOR_GREEN };
    fill_rect(dialog_x + dialog_w - 105, dialog_y + 100, 90, 32, connect_color);
    let btn_text: &[u8] = if connecting {
        b"Connecting"
    } else {
        b"Connect"
    };
    draw_string(dialog_x + dialog_w - 90, dialog_y + 108, btn_text, 0xFF0D1117);
}
