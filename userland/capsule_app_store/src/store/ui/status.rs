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

//! The strip along the bottom: what the keys do, and what the last
//! install request was told.

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::roles;
use nonos_toolkit::widgets::{text, Rect, Separator};

use crate::store::progress::Progress;
use crate::store::state::State;
use crate::store::tier_fit::hidden_line;

use super::bytes::as_str;
use super::metrics::{SMALL_PX, STATUS_H, STATUS_PAD_X};

pub fn paint(fb: &mut PaintBuffer, state: &State) {
    let (r, y) = (roles(), state.fb_h.saturating_sub(STATUS_H));
    fb.fill_rect(0, y, state.fb_w, STATUS_H, r.sunken.argb());
    Separator::new().draw(fb, Rect { x: 0, y, w: state.fb_w, h: 1 });
    let top = text::centre_top(y, STATUS_H, SMALL_PX);
    /*
     * Enter's word is the card's button, so the hint never disagrees with it.
     * With no NONOS disk Enter does nothing for a model, so it is not offered.
     */
    let current = state.current();
    let enter = current.map_or(&b"Install"[..], |l| l.progress.button(l.ready));
    let idle = current.is_some_and(|l| l.progress.needs_installed_system());
    let mut keys = alloc::vec::Vec::with_capacity(96);
    keys.extend_from_slice(b"up/down select    ");
    if !idle {
        keys.extend_from_slice(b"Enter ");
        keys.extend(enter.iter().map(u8::to_ascii_lowercase));
        keys.extend_from_slice(b"    ");
    }
    /* A large tier download through Nym or Anyone may be taken direct, by choice. */
    if current.is_some_and(|l| crate::store::install::direct_offered_for(state, l)) {
        keys.extend_from_slice(b"d download direct    ");
    }
    if current.is_some_and(|l| l.progress == Progress::Installed) {
        keys.extend_from_slice(b"u remove    ");
    }
    keys.extend_from_slice(b"/ search    r refresh    Esc close");
    text::left(fb, STATUS_PAD_X, top, as_str(&keys), r.muted, SMALL_PX);
    /* The answer to the last request sits opposite the keys. */
    let right = state.fb_w.saturating_sub(STATUS_PAD_X);
    if let Some(asked) = state.asked {
        text::right(fb, right, top, as_str(asked.label()), r.accent, SMALL_PX);
    } else if let Some(line) = hidden_line(state.hidden()) {
        /* The tiers that do not fit are counted, not shown (`tier_fit`). */
        text::right(fb, right, top, &line, r.muted, SMALL_PX);
    }
}
