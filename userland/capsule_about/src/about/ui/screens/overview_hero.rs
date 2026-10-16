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

use crate::about::data::admission::{self, Admission};
use crate::about::data::{abi, build, product};
use crate::about::format::trimmed;

use super::super::card;
use super::super::chip::chip;
use super::super::metrics::{
    BODY_PX, CARD_PAD, CHIP_H, HERO_H, HERO_META_TOP, HERO_SUB_TOP, HERO_TEXT_X, HERO_TITLE_TOP,
    VALUE_PX,
};
use super::super::text::{self, line};
use super::overview_mark::mark;

// The identity band: the mark, the product, and the four facts that name this
// exact image. The badge on the right is a passive label, not a control: it
// says how the kernel's spawn gate admitted this window, as the attestation
// registry records it, and is green only for an admission under a proof.
pub fn paint(fb: &mut PaintBuffer, y: i32, w: u32, admission: Admission) {
    let r = roles();
    card::panel(fb, 0, y, w, HERO_H);
    mark(fb, y);
    line(fb, HERO_TEXT_X, y + HERO_TITLE_TOP as i32, product::NAME, r.text.argb(), VALUE_PX);
    let sub = y + HERO_SUB_TOP as i32;
    let cut = text::fit(fb, product::TAGLINE, BODY_PX, w.saturating_sub(HERO_TEXT_X + CARD_PAD));
    line(fb, HERO_TEXT_X, sub, cut, r.text_2.argb(), BODY_PX);
    meta(fb, y + HERO_META_TOP as i32);
    badge(fb, y, w, admission);
}

fn meta(fb: &mut PaintBuffer, y: i32) {
    let r = roles();
    let mut x = line(fb, HERO_TEXT_X, y, trimmed(build::VERSION), r.text_2.argb(), BODY_PX);
    for (value, accent) in [(build::GIT_SHA, false), (build::ARCH, false), (abi::NAME, true)] {
        x = line(fb, x.max(0) as u32, y, b"   /   ", r.muted.argb(), BODY_PX);
        let fg = if accent { r.accent.argb() } else { r.text_2.argb() };
        x = line(fb, x.max(0) as u32, y, value, fg, BODY_PX);
    }
}

fn badge(fb: &mut PaintBuffer, y: i32, w: u32, admission: Admission) {
    let r = roles();
    let (label, pass, sub) = admission::badge(admission);
    let top = y + HERO_TITLE_TOP as i32;
    let bw = super::super::chip::width_of(label);
    let x = w.saturating_sub(CARD_PAD + bw);
    if top >= 0 && top + CHIP_H as i32 <= fb.height as i32 {
        chip(fb, x, top as u32, label, pass);
    }
    let sw = text::width_of(sub, BODY_PX);
    let sx = w.saturating_sub(CARD_PAD + sw);
    line(fb, sx, top + (CHIP_H + 10) as i32, sub, r.muted.argb(), BODY_PX);
}
