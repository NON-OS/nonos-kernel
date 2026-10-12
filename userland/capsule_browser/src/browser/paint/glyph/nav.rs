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

use super::pen::Pen;

pub fn back(fb: &mut PaintBuffer, p: &Pen) {
    p.poly(fb, &[(24, 38), (10, 24), (24, 10)]);
    p.line(fb, (38, 24), (10, 24));
}

pub fn forward(fb: &mut PaintBuffer, p: &Pen) {
    p.poly(fb, &[(24, 10), (38, 24), (24, 38)]);
    p.line(fb, (10, 24), (38, 24));
}

pub fn reload(fb: &mut PaintBuffer, p: &Pen) {
    p.arc(fb, 15, 3, 4);
    p.poly(fb, &[(2, 23), (9, 15), (16, 23)]);
}

pub fn home(fb: &mut PaintBuffer, p: &Pen) {
    p.poly(fb, &[(6, 22), (24, 7), (42, 22)]);
    p.poly(fb, &[(10, 19), (10, 41), (38, 41), (38, 19)]);
    p.poly(fb, &[(20, 41), (20, 29), (28, 29), (28, 41)]);
}

pub fn search(fb: &mut PaintBuffer, p: &Pen) {
    p.ring(fb, 21, 21, 14);
    p.line(fb, (31, 31), (42, 42));
}

pub fn lock(fb: &mut PaintBuffer, p: &Pen) {
    p.frame(fb, (9, 21), (39, 43), 4);
    p.poly(fb, &[(15, 21), (15, 14), (18, 9), (24, 7), (30, 9), (33, 14), (33, 21)]);
}

pub fn globe(fb: &mut PaintBuffer, p: &Pen) {
    p.ring(fb, 24, 24, 19);
    p.line(fb, (5, 24), (43, 24));
    p.poly(
        fb,
        &[(24, 5), (16, 14), (14, 24), (16, 34), (24, 43), (32, 34), (34, 24), (32, 14), (24, 5)],
    );
}
