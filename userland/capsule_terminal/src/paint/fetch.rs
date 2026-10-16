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

//! The fresh-terminal splash: the NONOS block banner over a crisp neofetch-style
//! panel of system facts. All text is anti-aliased TrueType.

use nonos_app_skeleton::PaintBuffer;
use nonos_libc::mk_uptime_ms;

use super::fetch_banner::draw_banner;
use super::fetch_palette::draw_palette;
use super::fetch_uptime::uptime_str;
use super::user_host::draw_fetch_id;
use crate::term::theme::types::Theme;

// Breathing room between the titlebar and the top of the banner. Anchored to
// the body rect so the art starts inside the content area, not butted against
// the chrome above it.
const BANNER_PAD: i32 = 14;
const RULE_W: i32 = 300;
const INFO_PX: f32 = 14.0;
const ROW: i32 = 20;

fn row(fb: &mut PaintBuffer, x: i32, y: i32, label: &str, value: &str, t: &Theme) {
    let _ = fb.text_ttf_mono(x, y, label, t.accent, INFO_PX);
    let _ = fb.text_ttf_mono(x + 96, y, value, t.fg, INFO_PX);
}

/// `swatches` are the program colours in force, shown the way neofetch does.
pub fn draw_fetch(
    fb: &mut PaintBuffer,
    x: u32,
    body_y: u32,
    right: u32,
    t: &Theme,
    swatches: &[u32],
) {
    let ix = x as i32;
    let edge = right as i32;
    let after = draw_banner(fb, ix, body_y as i32 + BANNER_PAD, edge, t);
    let _ = fb.text_ttf(ix, after + 4, "ZeroState Cryptographic OS", t.dim, 14.0);

    let mut y = after + 34;
    draw_fetch_id(fb, ix, y, INFO_PX, t);
    y += 8;
    fb.fill_rect(ix as u32, (y + 8) as u32, (edge - ix).clamp(0, RULE_W) as u32, 1, t.dim);
    y += 24;

    row(fb, ix, y, "os", super::fetch_boot::os_line(), t);
    y += ROW;
    let mut kb = [0u8; 48];
    let kn = super::fetch_version::kernel_line(&mut kb);
    row(fb, ix, y, "kernel", core::str::from_utf8(&kb[..kn]).unwrap_or(""), t);
    y += ROW;
    row(fb, ix, y, "shell", "nox   (type 'help')", t);
    y += ROW;
    // The kernel's record of who signed this terminal, not a fixed claim.
    let signed = crate::command::builtin::receipt::own_line();
    row(fb, ix, y, "signed", core::str::from_utf8(signed).unwrap_or(""), t);
    y += ROW;
    row(fb, ix, y, "arch", super::fetch_arch::arch(), t);
    y += ROW;

    // The system's uptime, as `uptime` reports it; it was the tab's age.
    let mut buf = [0u8; 24];
    let n = uptime_str(mk_uptime_ms().max(0) as u64, &mut buf);
    let up = core::str::from_utf8(&buf[..n]).unwrap_or("");
    row(fb, ix, y, "uptime", up, t);
    y += ROW + 6;

    draw_palette(fb, ix as u32, y as u32, swatches);
}
