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

//! The strip along the bottom: count, load, memory, uptime, posture, sort.

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::{roles, Opaque};
use nonos_toolkit::widgets::{Rect, Separator};

use crate::pm::format::{mem_human, percent, u32_decimal, uptime_human};
use crate::pm::format_sys::load_human;
use crate::pm::security::Level;
use crate::pm::state::notes::{strip_note, KEYS_HINT};
use crate::pm::state::State;

use super::metrics::{BODY_PX, PANE_PAD_X, STATUS_GAP, STATUS_GROUP_GAP, STATUS_H};
use super::text;

pub fn paint(fb: &mut PaintBuffer, state: &State) {
    let (r, y) = (roles(), fb.height.saturating_sub(STATUS_H));
    fb.fill_rect(0, y, fb.width, STATUS_H, r.sunken.argb());
    Separator::new().draw(fb, Rect { x: 0, y, w: fb.width, h: 1 });
    let top = text::centred_top(y, STATUS_H, BODY_PX);
    let mut buf = [0u8; 32];
    let total = state.rows.len() as u32;
    let visible = state.filtered().len() as u32;
    let mut n = u32_decimal(total, &mut buf);
    if visible != total {
        n = u32_decimal(visible, &mut buf);
        buf[n] = b'/';
        n += 1;
        n += u32_decimal(total, &mut buf[n..]);
    }
    let mut x = pair(fb, PANE_PAD_X, top, b"PROCS", &buf[..n]);
    let n = percent(state.sys.busy_pct, &mut buf);
    x = pair(fb, x, top, b"CPU", &buf[..n]);
    let n = mem_human(state.sys.mem_used_kb(), &mut buf);
    x = pair(fb, x, top, b"MEM", &buf[..n]);
    let n = load_human(state.sys.load[0], &mut buf);
    x = pair(fb, x, top, b"LOAD", &buf[..n]);
    let n = uptime_human(state.sys.uptime_ms / 1000, &mut buf);
    x = pair(fb, x, top, b"UP", &buf[..n]);
    let (tone, label) = posture(state);
    let after = text::left(fb, x, top, label, tone, BODY_PX).max(0) as u32 + STATUS_GROUP_GAP;
    let right_x = fb.width.saturating_sub(PANE_PAD_X);
    text::right(fb, right_x, top, state.sort.label(), r.accent, BODY_PX);
    let sort_w = text::width(fb, state.sort.label(), BODY_PX);
    let hint_x = right_x.saturating_sub(sort_w + STATUS_GROUP_GAP);
    /*
     * A kill prompt, its outcome or an unreadable table replaces the key hint,
     * cut to the room left of the sort label so it never runs under the counts.
     */
    let note = strip_note(state.notice, state.status);
    let ink = if note == KEYS_HINT { r.muted } else { r.warn };
    let cut = text::fit(fb, note, BODY_PX, hint_x.saturating_sub(after));
    text::right(fb, hint_x, top, cut, ink, BODY_PX);
}

fn pair(fb: &mut PaintBuffer, x: u32, top: u32, label: &[u8], value: &[u8]) -> u32 {
    let r = roles();
    let after = text::left(fb, x, top, label, r.muted, BODY_PX).max(0) as u32 + STATUS_GAP;
    text::mono(fb, after, top, value, r.text, BODY_PX).max(0) as u32 + STATUS_GROUP_GAP
}

fn posture(state: &State) -> (Opaque, &'static [u8]) {
    let r = roles();
    match state.alerts.iter().map(|a| a.level).max() {
        None => (r.ok, b"NO FINDINGS"),
        Some(Level::Info) => (r.ok, Level::Info.label()),
        Some(Level::Warn) => (r.warn, Level::Warn.label()),
        Some(Level::Critical) => (r.danger, Level::Critical.label()),
    }
}
