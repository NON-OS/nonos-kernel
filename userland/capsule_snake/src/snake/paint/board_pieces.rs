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
use nonos_toolkit::theme::derive::with_alpha;
use nonos_toolkit::theme::roles;

use crate::snake::state::Game;
use crate::snake::ui::play_geom::Board;

use super::board_cell::{cell, centre, radius};
use super::diamond;

pub fn paint(game: &Game, fb: &mut PaintBuffer, b: &Board) {
    let (r, theme) = (radius(b), roles());
    for wall in game.walls.iter() {
        let block = cell(b, *wall);
        fb.fill_round(block.0, block.1, block.2, block.3, r, theme.border_strong.argb());
        fb.stroke_round(block.0, block.1, block.2, block.3, r, 1, theme.muted.argb());
    }
    food(fb, b, game.food);
    if let Some(at) = game.power {
        power(fb, b, at);
    }
}

fn food(fb: &mut PaintBuffer, b: &Board, at: (i16, i16)) {
    let (cx, cy) = centre(b, at);
    let span = cell(b, at).2 / 2;
    let (thick, danger) = ((span / 3).max(1), roles().danger.argb());
    fb.ring(cx, cy, span, thick, with_alpha(danger, 0x66));
    fb.circle(cx, cy, span.saturating_sub(thick + 1).max(1), danger);
}

fn power(fb: &mut PaintBuffer, b: &Board, at: (i16, i16)) {
    let (cx, cy) = centre(b, at);
    let (span, accent) = (cell(b, at).2 / 2, roles().accent.argb());
    diamond::ring(fb, cx, cy, span, with_alpha(accent, 0x66));
    diamond::fill(fb, cx, cy, span.saturating_sub(2), accent);
}
