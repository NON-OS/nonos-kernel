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

pub fn paint(fb: &mut PaintBuffer) {
    let r = roles();
    let (accent, text) = (r.accent.argb(), r.text.argb());
    fb.clear(r.bg.argb());
    fb.fill_rect(0, 0, 360, 4, accent);
    fb.text_scaled(24, 40, b"hello, NONOS", accent, 2);
    fb.text(24, 88, b"a signed, attested capsule", text);
    fb.text(24, 110, b"built from the quickstart", text);
    fb.text(24, 148, b"press Esc to close", r.quiet.argb());
}
