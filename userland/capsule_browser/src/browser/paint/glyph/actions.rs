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

pub fn plus(fb: &mut PaintBuffer, p: &Pen) {
    p.line(fb, (24, 10), (24, 38));
    p.line(fb, (10, 24), (38, 24));
}

pub fn close(fb: &mut PaintBuffer, p: &Pen) {
    p.line(fb, (12, 12), (36, 36));
    p.line(fb, (36, 12), (12, 36));
}

pub fn sidebar(fb: &mut PaintBuffer, p: &Pen) {
    p.frame(fb, (6, 8), (42, 40), 5);
    p.line(fb, (18, 8), (18, 40));
}

pub fn sliders(fb: &mut PaintBuffer, p: &Pen) {
    for (v, knob) in [(12, 30), (24, 16), (36, 34)] {
        p.line(fb, (6, v), (knob - 5, v));
        p.ring(fb, knob, v, 4);
        p.line(fb, (knob + 5, v), (42, v));
    }
}
