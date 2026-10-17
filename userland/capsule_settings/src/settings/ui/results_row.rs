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
use nonos_policy_proto::{label_of, Field};
use nonos_toolkit::widgets::{Ink, Rect, Row, Scrolled, State as Look};

use crate::settings::section::Section;
use crate::settings::section_text::nav;

use super::bytes::as_str;

/// One search result at `at`, in content coordinates, through the toolkit
/// row: the setting, the section that holds it and a chevron, since choosing
/// it goes there. `look` carries the keyboard cursor and the pointer.
pub fn paint(
    fb: &mut PaintBuffer,
    field: Field,
    section: Section,
    scroll: u32,
    at: Rect,
    look: Look,
) {
    let line = Row::new(as_str(label_of(field))).value(nav(section)).value_ink(Ink::Muted);
    line.chevron().state(look).draw(&mut Scrolled::new(fb, scroll), at);
}
