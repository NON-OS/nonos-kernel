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

//! How the machine's dangerous authority is spread, and what has moved.
//!
//! This card used to read "20" over "of 44 processes". That number is already on
//! screen as a column of shields, and it answers a question nobody asks: whether
//! twenty capsules are privileged matters far less than which authority they
//! hold, because the four sensitive classes are not interchangeable. One capsule
//! with raw hardware reach is a different machine from one with debug.
//!
//! Nothing here is measured or inferred. Every capsule declared its authority in
//! a signed manifest and the kernel granted exactly that set, so these are the
//! grants themselves, not a guess from behaviour.
//!
//! Counts come from `Monitor::posture`, which the security screen also reads, so
//! the two cannot disagree; the class order and colours come from
//! `risk_strip::CLASSES`, so a row's slots and this card cannot either.

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::font::ttf::line_height;
use nonos_toolkit::icons::{draw, IconId};
use nonos_toolkit::theme::roles;
use nonos_toolkit::widgets::{Card, Rect};

use crate::pm::state::State;

use super::super::metrics::{BODY_PX, CARD_H, CARD_ICON, CARD_LABEL_GAP};
use super::super::risk_strip::CLASSES;
use super::super::text;
use super::ovw_auth_labels::LABELS;
use super::ovw_auth_row::row;

pub(super) const PAD: u32 = 8;
const CAPTION_GAP: u32 = 2;

pub(super) fn paint(state: &State, fb: &mut PaintBuffer, x: u32, y: u32, w: u32) {
    let r = roles();
    Card::new().draw(fb, Rect { x, y, w, h: CARD_H });
    let body = line_height(BODY_PX).max(1) as u32;
    let cap_y = y + PAD;
    let icon_y = cap_y + body.saturating_sub(CARD_ICON) / 2;
    draw(fb, IconId::SettingsSecurity, x + PAD, icon_y, CARD_ICON, r.muted.argb());
    text::left(fb, x + PAD + CARD_ICON + CARD_LABEL_GAP, cap_y, b"AUTHORITY", r.muted, BODY_PX);

    let now = &state.monitor.posture;
    let start = state.monitor.start_posture();

    /*
     * Rows are exactly one line tall and anchored under the caption, so they can
     * never overlap it however the face measures. Whatever is left over falls at
     * the bottom of the card rather than being spread between the rows, which
     * keeps a four-row stack reading as one block.
     */
    let top = cap_y + body + CAPTION_GAP;
    for (i, (mask, tone)) in CLASSES.iter().enumerate() {
        let held = now.held(*mask);
        let was = start.held(*mask);
        row(fb, (x, top + body * i as u32, w), body, LABELS[i], (held, was), *tone);
    }
}
