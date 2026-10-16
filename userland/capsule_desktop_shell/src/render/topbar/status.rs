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

//! The right-hand status cluster: battery (a gauge for a reading, plain
//! words for no battery or an unreadable one), network and the date-time stamp, all from live readings, set
//! straight on the bar with no tile behind them. The tray's labels sit just
//! left of it.

use super::battery_glyph::battery_glyph;
use super::metrics::{batt_glyph_w, gap, net_glyph_w, search_glyph_w};
use super::net_glyph::net_glyph;
use super::search_box::{cluster_x, fitted, has_gauge, search_box};
use super::search_glyph::search_glyph;
use crate::render::layout::menubar_rect;
use crate::render::text_aa::text_aa_bytes;
use crate::render::ui_font::{px, scale, top_y_centered, STATUS_PX};
use crate::state::indicators::clock_stamp::{stamp, STAMP_LEN};
use crate::state::indicators::{battery, battery_text};
use crate::state::Context;

pub(super) fn status(ctx: &Context) {
    let bar = menubar_rect(ctx.width);
    // Read once a second by the tick (refresh_clock), not here: the chrome is
    // painted on every menu hover and press, and each paint asked the DHCP
    // client, on the shell's only thread, which waits while it gets an address.
    let online = ctx.net_was_online;
    let batt = battery::percent();
    let pct = batt.percent();
    let mut bbuf = [0u8; battery_text::LABEL_MAX];
    let blen = battery_text::label(batt, &mut bbuf);
    let mut sbuf = [b'-'; STAMP_LEN];
    let when: &[u8] = match stamp(&mut sbuf, ctx.clock_24h, ctx.tz_hours) {
        Some(n) => &sbuf[..n],
        None => b"--:--",
    };
    let btext = fitted(ctx, &bbuf[..blen], when);
    let Some(mut x) = cluster_x(ctx, btext, when) else {
        return;
    };
    super::tray::tray(ctx, x);
    let glyph_y = bar.y + (bar.height - 12 * scale()) / 2;
    let text_y = top_y_centered(bar.y, bar.height, STATUS_PX);
    if !btext.is_empty() {
        if has_gauge(btext) {
            battery_glyph(ctx, x, glyph_y, pct);
            x += batt_glyph_w() + px(6);
        }
        x = text_aa_bytes(ctx, x, text_y, btext, ctx.palette.text_dim, STATUS_PX) + gap();
    }
    net_glyph(ctx, x, glyph_y, online);
    x += net_glyph_w() + gap();
    if let Some((sx, sy, _)) = search_box(ctx, btext, when) {
        search_glyph(ctx, sx, sy);
    }
    x += search_glyph_w() + gap();
    text_aa_bytes(ctx, x, text_y, when, ctx.palette.text, STATUS_PX);
}
