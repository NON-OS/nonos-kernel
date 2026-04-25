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

use crate::graphics::font::draw_char;
use crate::graphics::framebuffer::fill_rounded_rect;
use crate::sdk::registry::{list_apps, AppInfo};

const CARD: u32 = 0xFF14141C;
const DIM: u32 = 0xFF606068;

fn txt(x: u32, y: u32, t: &[u8], c: u32) {
    for (i, &ch) in t.iter().enumerate() {
        draw_char(x + i as u32 * 8, y, ch, c);
    }
}

pub(super) fn draw(x: u32, y: u32, w: u32, _h: u32) {
    txt(x + 20, y + 20, b"My Published Apps", 0xFFFFFFFF);
    let apps = list_apps();
    if apps.is_empty() {
        txt(x + 20, y + 60, b"No apps published yet", DIM);
        txt(x + 20, y + 80, b"Go to Publish tab to create one", DIM);
        return;
    }
    let mut cy = y + 50;
    for app in apps.iter().take(10) {
        draw_app_card(x + 20, cy, w - 40, app);
        cy += 70;
    }
}

fn draw_app_card(x: u32, y: u32, w: u32, app: &AppInfo) {
    fill_rounded_rect(x, y, w, 60, 8, CARD);
    let name = &app.manifest.name;
    let len = name.iter().position(|&c| c == 0).unwrap_or(64);
    txt(x + 16, y + 12, &name[..len], 0xFFFFFFFF);
    txt(x + 16, y + 34, b"Installs: ", DIM);
    let cnt = app.run_count;
    let mut buf = [0u8; 8];
    let dlen = format_num(cnt, &mut buf);
    txt(x + 96, y + 34, &buf[..dlen], 0xFF00D4FF);
}

fn format_num(mut n: u32, buf: &mut [u8; 8]) -> usize {
    if n == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut i = 0;
    while n > 0 && i < 8 {
        buf[7 - i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    buf.copy_within(8 - i.., 0);
    i
}

pub(super) fn handle_click(_rx: u32, _ry: u32) -> bool {
    false
}
