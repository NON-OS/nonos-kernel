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

//! One class of authority, as one row.

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::roles;
use nonos_toolkit::widgets::Tone;

use crate::pm::format::u32_decimal;

use super::super::metrics::{BODY_PX, CARD_LABEL_GAP, NUM_PX, RISK_SLOT_GAP, RISK_SLOT_W};
use super::super::text;
use super::ovw_auth_delta::delta;
use super::ovw_authority::PAD;

// The swatch is the strip's slot, so the eye that learned the four positions in
// the table reads this card without relearning them.
const KEY_H: u32 = 12;

// One class: its colour key, its name, the change since the session started, and
// the count itself hard against the right edge so four rows align on their last
// digit. A class nobody holds keeps its row and dims instead of vanishing, since
// an empty row is a fact and a missing one is a gap in the reader's knowledge.
pub(super) fn row(
    fb: &mut PaintBuffer,
    at: (u32, u32, u32),
    h: u32,
    label: &[u8],
    counts: (u32, u32),
    tone: Tone,
) {
    let (r, (x, y, w)) = (roles(), at);
    let (held, was) = counts;
    let tint = if held == 0 { r.muted } else { tone.colour(&r) };

    let key_y = y + h.saturating_sub(KEY_H) / 2;
    let key = if held == 0 { r.border_strong } else { tone.colour(&r) };
    fb.fill_rect(x + PAD, key_y, RISK_SLOT_W, KEY_H, key.argb());

    let top = text::centred_top(y, h, BODY_PX);
    let text_x = x + PAD + RISK_SLOT_W + RISK_SLOT_GAP + CARD_LABEL_GAP;
    text::left(fb, text_x, top, label, tint, BODY_PX);

    let mut buf = [0u8; 12];
    let n = u32_decimal(held, &mut buf);
    let right = x + w.saturating_sub(PAD);
    text::mono_right(fb, right, top, &buf[..n], tint, NUM_PX);

    /*
     * The delta is drawn only when there is one. A column of "+0" would be four
     * more numbers to read past on a card whose whole point is that a change is
     * rare enough to be worth noticing.
     */
    if held != was {
        let count_w = text::mono_width(fb, &buf[..n], NUM_PX);
        let delta_right = right.saturating_sub(count_w + CARD_LABEL_GAP);
        let mut mark = [0u8; 12];
        let m = delta(held, was, &mut mark);
        let tone = if held > was { r.warn } else { r.ok };
        text::mono_right(fb, delta_right, top, &mark[..m], tone, NUM_PX);
    }
}
