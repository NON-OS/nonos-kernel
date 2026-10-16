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
use nonos_toolkit::widgets::Card;

use crate::pm::state::State;

use super::super::chrome::Rect;
use super::super::metrics::{BODY_PX, CARD_GAP, PANEL_HEAD_H, PANEL_PAD};
use super::super::text;
use super::{cpu_bands, cpu_chart, cpu_kernel};

// The chart takes a fixed height so the three panels below it always start
// on the same line whatever the window does. Everything else flexes off r.w,
// which is the whole pane here because the CPU screen docks no inspector.
const CHART_H: u32 = 220;

pub fn paint(state: &State, fb: &mut PaintBuffer, r: &Rect) {
    cpu_chart::paint(state, fb, r, CHART_H);
    let y = r.y + CHART_H + CARD_GAP;
    let h = r.h.saturating_sub(CHART_H + CARD_GAP);
    let w = r.w.saturating_sub(CARD_GAP * 2) / 3;
    cpu_bands::states(state, fb, &Rect { x: r.x, y, w, h });
    cpu_bands::consumers(state, fb, &Rect { x: r.x + w + CARD_GAP, y, w, h });
    cpu_kernel::kernel(state, fb, &Rect { x: r.x + (w + CARD_GAP) * 2, y, w, h });
}

// Every band on this screen is the same card: the toolkit card and a caption
// line, with the y of the first content row handed back so no
// caller re-derives the header height.
pub(super) fn panel(fb: &mut PaintBuffer, r: &Rect, caption: &[u8]) -> u32 {
    Card::new().draw(fb, *r);
    let top = text::centred_top(r.y, PANEL_HEAD_H, BODY_PX);
    text::left(fb, r.x + PANEL_PAD, top, caption, roles().text, BODY_PX);
    r.y + PANEL_HEAD_H
}
