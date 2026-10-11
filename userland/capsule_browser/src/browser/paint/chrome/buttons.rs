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

use crate::browser::paint::chrome::constants::{DIM, FG, TOOLBAR_BG};

/* A chevron pointing left, or right when `mirror` is set. */
pub(super) fn chevron(fb: &mut PaintBuffer, x: u32, mirror: bool, color: u32) {
    let at = |dx: u32| if mirror { x + 14 - dx } else { x + dx };
    fb.fill_rect(at(4), 22, 2, 8, color);
    fb.fill_rect(at(6), 20, 2, 2, color);
    fb.fill_rect(at(6), 30, 2, 2, color);
    fb.fill_rect(at(8), 18, 2, 2, color);
    fb.fill_rect(at(8), 32, 2, 2, color);
}

pub(super) fn reload(fb: &mut PaintBuffer, x: u32) {
    fb.fill_rect(x + 2, 18, 12, 2, FG);
    fb.fill_rect(x + 2, 32, 12, 2, FG);
    fb.fill_rect(x + 2, 18, 2, 8, FG);
    fb.fill_rect(x + 12, 26, 2, 8, FG);
    fb.fill_rect(x + 10, 16, 2, 2, FG);
    fb.fill_rect(x + 12, 16, 2, 4, FG);
}

/* The Stop cross shown in place of Reload while a page loads. */
pub(super) fn stop(fb: &mut PaintBuffer, x: u32) {
    for i in 0..12 {
        fb.fill_rect(x + 2 + i, 19 + i, 2, 2, FG);
        fb.fill_rect(x + 13 - i, 19 + i, 2, 2, FG);
    }
}

pub(super) fn home(fb: &mut PaintBuffer, x: u32) {
    fb.fill_rect(x + 6, 16, 4, 2, FG);
    fb.fill_rect(x + 4, 18, 8, 2, FG);
    fb.fill_rect(x + 2, 20, 12, 2, FG);
    fb.fill_rect(x + 4, 22, 8, 12, FG);
    fb.fill_rect(x + 7, 28, 2, 6, TOOLBAR_BG);
}

pub(super) fn hamburger(fb: &mut PaintBuffer) {
    let x = fb.width.saturating_sub(36);
    fb.fill_rect(x, 18, 16, 2, DIM);
    fb.fill_rect(x, 25, 16, 2, DIM);
    fb.fill_rect(x, 32, 16, 2, DIM);
}
