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
use crate::graphics::framebuffer::{fill_rect, fill_rounded_rect};
use crate::sdk::registry::{app_count, list_apps};

const CARD: u32 = 0xFF14141C;
const ACCENT: u32 = 0xFF00D4FF;
const DIM: u32 = 0xFF606068;

fn txt(x: u32, y: u32, t: &[u8], c: u32) {
    for (i, &ch) in t.iter().enumerate() {
        draw_char(x + i as u32 * 8, y, ch, c);
    }
}

pub(super) fn draw(x: u32, y: u32, w: u32, _h: u32) {
    txt(x + 20, y + 20, b"Analytics Dashboard", 0xFFFFFFFF);
    draw_stat_card(x + 20, y + 50, b"Total Apps", app_count());
    draw_stat_card(x + 180, y + 50, b"Total Installs", total_installs());
    draw_stat_card(x + 340, y + 50, b"Revenue (NOX)", total_revenue());
    draw_chart(x + 20, y + 170, w - 40, 150);
}

fn draw_stat_card(x: u32, y: u32, label: &[u8], value: u32) {
    fill_rounded_rect(x, y, 140, 100, 8, CARD);
    txt(x + 16, y + 16, label, DIM);
    let mut buf = [0u8; 10];
    let len = format_num(value, &mut buf);
    txt(x + 16, y + 50, &buf[..len], ACCENT);
}

fn draw_chart(x: u32, y: u32, w: u32, h: u32) {
    fill_rounded_rect(x, y, w, h, 8, CARD);
    txt(x + 16, y + 16, b"Install Trend (7 days)", DIM);
    fill_rect(x + 16, y + h - 20, w - 32, 1, 0xFF252530);
    let bars = [30u32, 45, 60, 40, 80, 65, 90];
    let bw = (w - 64) / 7;
    for (i, &v) in bars.iter().enumerate() {
        let bh = (v * (h - 60)) / 100;
        fill_rect(x + 24 + i as u32 * bw, y + h - 24 - bh, bw - 8, bh, ACCENT);
    }
}

fn total_installs() -> u32 {
    list_apps().iter().map(|a| a.run_count).sum()
}
fn total_revenue() -> u32 {
    list_apps().iter().map(|a| a.manifest.price_nox * a.run_count).sum()
}

fn format_num(mut n: u32, buf: &mut [u8; 10]) -> usize {
    if n == 0 {
        buf[0] = b'0';
        return 1;
    }
    let mut i = 0;
    while n > 0 && i < 10 {
        buf[9 - i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }
    buf.copy_within(10 - i.., 0);
    i
}
