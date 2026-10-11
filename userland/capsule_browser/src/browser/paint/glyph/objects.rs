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

use super::fill::fill_polygon;
use super::pen::Pen;

const STAR: [(i32, i32); 11] = [
    (24, 4),
    (30, 17),
    (44, 19),
    (34, 29),
    (36, 43),
    (24, 36),
    (12, 43),
    (14, 29),
    (4, 19),
    (18, 17),
    (24, 4),
];

const SHIELD: [(i32, i32); 11] = [
    (24, 4),
    (31, 8),
    (40, 10),
    (40, 26),
    (36, 34),
    (24, 43),
    (12, 34),
    (8, 26),
    (8, 10),
    (17, 8),
    (24, 4),
];

pub fn star(fb: &mut PaintBuffer, p: &Pen, filled: bool) {
    if filled {
        fill_polygon(fb, p, &STAR);
    }
    p.poly(fb, &STAR);
}

pub fn shield(fb: &mut PaintBuffer, p: &Pen) {
    p.poly(fb, &SHIELD);
}
