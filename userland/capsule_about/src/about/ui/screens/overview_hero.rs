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

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::roles;
use nonos_toolkit::widgets::text::{left, truncate, width};
use nonos_toolkit::widgets::{Pill, Rect, Tone};

use crate::about::data::admission::{self, Admission};
use crate::about::data::{abi, build, product};
use crate::about::format::trimmed;

use super::super::card;
use super::super::metrics::{
    BODY_PX, CARD_PAD, HERO_H, HERO_META_TOP, HERO_SUB_TOP, HERO_TEXT_X, HERO_TITLE_TOP, VALUE_PX,
};
use super::super::mono::valid;
use super::overview_mark::mark;

// The identity band: the mark, the product, and the four facts that name this
// exact image. The badge on the right is a passive label, not a control: it
// says how the kernel's spawn gate admitted this window, as the attestation
// registry records it, and is green only for an admission under a proof.
pub fn paint(fb: &mut PaintBuffer, y: i32, w: u32, admission: Admission) {
    let r = roles();
    card::panel(fb, 0, y, w, HERO_H);
    mark(fb, y);
    left(fb, HERO_TEXT_X, y + HERO_TITLE_TOP as i32, valid(product::NAME), r.text, VALUE_PX);
    let sub = y + HERO_SUB_TOP as i32;
    let cut = truncate(valid(product::TAGLINE), w.saturating_sub(HERO_TEXT_X + CARD_PAD), BODY_PX);
    left(fb, HERO_TEXT_X, sub, &cut, r.text_2, BODY_PX);
    meta(fb, y + HERO_META_TOP as i32);
    badge(fb, y, w, admission);
}

fn meta(fb: &mut PaintBuffer, y: i32) {
    let r = roles();
    let mut x = left(fb, HERO_TEXT_X, y, valid(trimmed(build::VERSION)), r.text_2, BODY_PX);
    for (value, accent) in [(build::GIT_SHA, false), (build::ARCH, false), (abi::NAME, true)] {
        x = left(fb, x.max(0) as u32, y, "   /   ", r.muted, BODY_PX);
        let fg = if accent { r.accent } else { r.text_2 };
        x = left(fb, x.max(0) as u32, y, valid(value), fg, BODY_PX);
    }
}

fn badge(fb: &mut PaintBuffer, y: i32, w: u32, admission: Admission) {
    let r = roles();
    let (label, pass, sub) = admission::badge(admission);
    let top = y + HERO_TITLE_TOP as i32;
    let pill = Pill::new(valid(label)).tone(if pass { Tone::Ok } else { Tone::Danger }).dot();
    let (bw, bh) = pill.size();
    let x = w.saturating_sub(CARD_PAD + bw);
    if top >= 0 && top + bh as i32 <= fb.height as i32 {
        pill.draw(fb, Rect { x, y: top as u32, w: bw, h: bh });
    }
    let sw = width(valid(sub), BODY_PX);
    let sx = w.saturating_sub(CARD_PAD + sw);
    left(fb, sx, top + (bh + 10) as i32, valid(sub), r.muted, BODY_PX);
}
