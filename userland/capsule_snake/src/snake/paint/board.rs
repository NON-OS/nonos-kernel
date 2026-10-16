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

use crate::snake::grid::{COLS, ROWS};
use crate::snake::state::Game;
use crate::snake::ui::metrics::RADIUS_PANEL;
use crate::snake::ui::play_geom::Board;

use super::{board_pieces, board_snake};

pub fn paint(game: &Game, fb: &mut PaintBuffer, b: &Board) {
    ground(fb, b);
    board_pieces::paint(game, fb, b);
    board_snake::paint(game, fb, b);
}

fn ground(fb: &mut PaintBuffer, b: &Board) {
    let r = roles();
    fb.fill_round(b.x, b.y, b.w, b.h, RADIUS_PANEL, r.inset.argb());
    fb.stroke_round(b.x, b.y, b.w, b.h, RADIUS_PANEL, 1, r.border.argb());
    dots(fb, b);
}

// A dot at every cell corner rather than a ruled grid: the lattice has to read
// as depth behind the snake, not as a second set of walls.
fn dots(fb: &mut PaintBuffer, b: &Board) {
    let border = roles().border.argb();
    let d = (b.cell / 12).max(1);
    for row in 1..ROWS as u32 {
        for col in 1..COLS as u32 {
            let x = b.x + col * b.cell - d / 2;
            let y = b.y + row * b.cell - d / 2;
            fb.blend_rect(x, y, d, d, border);
        }
    }
}
