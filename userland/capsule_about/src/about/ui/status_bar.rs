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
use nonos_toolkit::widgets::{Ink, Rect, Row, Separator};

use crate::about::state::State;

use super::metrics::STATUS_H;

// The strip under every screen. Left is what the window is licensed under,
// right is how to leave it: the two facts that are true on all five sections
// and therefore belong to the frame rather than to any one of them.
pub fn paint(fb: &mut PaintBuffer, state: &State) {
    let r = roles();
    let y = state.fb_h.saturating_sub(STATUS_H);
    let strip = Rect { x: 0, y, w: state.fb_w, h: STATUS_H };
    fb.fill_rect(0, y, state.fb_w, STATUS_H, r.sunken.argb());
    Separator::new().draw(fb, Rect { h: 1, ..strip });
    let row = Row::new("License AGPL-3.0").value("Tab cycles sections    Esc closes");
    row.value_ink(Ink::Muted).draw(fb, strip);
}
