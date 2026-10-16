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

use super::code::{Matrix, PAYLOAD};
use super::draw::{draw_matrix, MARGIN};

const TITLE_Y: i32 = 20;
const PAYLOAD_Y: i32 = 48;
const MATRIX_TOP: u32 = 76;

pub fn paint(fb: &mut PaintBuffer, matrix: Option<&Matrix>) {
    let r = roles();
    fb.clear(r.bg.argb());
    fb.fill_rect(0, 0, fb.width, 4, r.accent.argb());
    fb.text_ttf(MARGIN, TITLE_Y, "qr generator", r.accent.argb(), 19.0);
    fb.text_ttf(MARGIN, PAYLOAD_Y, PAYLOAD, r.text.argb(), 14.0);
    let Some(matrix) = matrix else {
        fb.text_ttf(MARGIN, MATRIX_TOP as i32, "encode failed", r.danger.argb(), 15.0);
        return;
    };
    let bottom = draw_matrix(fb, matrix, MATRIX_TOP);
    fb.text_ttf(MARGIN, bottom as i32 + 12, "esc closes this window", r.quiet.argb(), 13.0);
}
