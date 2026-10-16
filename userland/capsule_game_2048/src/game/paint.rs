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
use nonos_toolkit::theme::contrast::{at_least, BODY, LARGE};
use nonos_toolkit::theme::derive::mix;
use nonos_toolkit::theme::{roles, Roles};
use tools_2048::Game;

use super::decimal::{render_u32, DIGITS};

const ORIGIN_X: u32 = 33;
const ORIGIN_Y: u32 = 150;
const TILE: u32 = 66;
const STEP: u32 = 76;

/// The game is laid out at its opening window's size. A larger window
/// (green, full screen) gets the same game centred on the ground, which
/// fills the whole window; it was drawn in the top left corner.
const LAYOUT_W: u32 = super::manifest::WIDTH;
const LAYOUT_H: u32 = super::manifest::HEIGHT;

pub fn paint(fb: &mut PaintBuffer, game: &Game<4>, over: bool) {
    let theme = roles();
    let (accent, text) = (theme.accent.argb(), theme.text.argb());
    fb.clear(theme.bg.argb());
    let ox = fb.width.saturating_sub(LAYOUT_W) / 2;
    let oy = fb.height.saturating_sub(LAYOUT_H) / 2;
    fb.text_scaled(ox + 24, oy + 34, b"2048", accent, 4);
    fb.text(ox + 210, oy + 40, b"SCORE", theme.muted.argb());
    let mut sbuf = [0u8; DIGITS];
    fb.text_scaled(ox + 210, oy + 58, render_u32(game.score() as u32, &mut sbuf), text, 2);
    let board_bg = theme.surface.argb();
    fb.fill_rect(ox + ORIGIN_X - 9, oy + ORIGIN_Y - 9, STEP * 4, STEP * 4, board_bg);
    let board = game.board();
    for r in 0..4 {
        for c in 0..4 {
            let v = board[r][c];
            let x = ox + ORIGIN_X + c as u32 * STEP;
            let y = oy + ORIGIN_Y + r as u32 * STEP;
            let tile = tile_color(&theme, v);
            fb.fill_rect(x, y, TILE, TILE, tile);
            if v != 0 {
                let mut tbuf = [0u8; DIGITS];
                let digits = render_u32(v as u32, &mut tbuf);
                let tx = x + TILE / 2 - digits.len() as u32 * 5;
                fb.text_scaled(tx, y + TILE / 2 - 8, digits, tile_ink(&theme, tile), 2);
            }
        }
    }
    if over {
        fb.text_scaled(ox + 64, oy + 250, b"GAME OVER", accent, 4);
    }
}

/// A categorical scale over the theme's hues: each of accent, warn, danger and
/// ok first as a light tint of the board, then solid, so neighbouring values
/// always differ in strength and each pair of steps in hue. 512 and 1024 take
/// even blends of two hues and anything from 2048 up the text colour itself.
/// An empty cell is the inset ground.
fn tile_color(r: &Roles, v: u64) -> u32 {
    let (board, accent) = (r.surface.argb(), r.accent.argb());
    let (ok, warn, danger) = (r.ok.argb(), r.warn.argb(), r.danger.argb());
    if v == 0 {
        return r.inset.argb();
    }
    match v.trailing_zeros() {
        1 => mix(board, accent, 32),
        2 => accent,
        3 => mix(board, warn, 32),
        4 => warn,
        5 => mix(board, danger, 32),
        6 => danger,
        7 => mix(board, ok, 32),
        8 => ok,
        9 => mix(warn, ok, 128),
        10 => mix(danger, accent, 128),
        _ => r.text.argb(),
    }
}

/// The text colour when it reads on the tile at the body floor; otherwise the
/// ground when that does; otherwise text again if it clears the large-text
/// floor, which only a low-contrast scheme such as Solar needs.
fn tile_ink(r: &Roles, tile: u32) -> u32 {
    let (text, ground) = (r.text.argb(), r.bg.argb());
    let reads = at_least(text, tile, BODY);
    if reads || !at_least(ground, tile, BODY) && at_least(text, tile, LARGE) {
        text
    } else {
        ground
    }
}
