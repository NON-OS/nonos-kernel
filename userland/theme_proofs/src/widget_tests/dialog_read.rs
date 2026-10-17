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

//! Dialog: the title and the body's lines, whole or cut with `…`, read on
//! the panel as body text at 4.5:1, the note at 4.5:1 in every tone, and
//! each kind of button's label at 4.5:1 plain, hovered, pressed, held,
//! focused and all at once, in every scheme and high contrast, read back
//! from the pixels drawn. Disabled need only be drawn visibly. The panel
//! is opaque, so the inks are read over one ground, the scheme's `bg`.

use nonos_toolkit::theme::roles;
use nonos_toolkit::widgets::State;

use super::dialog_inks::reads;
use super::read::{reach, NONE};
use super::serial::{per_theme, serial};

#[test]
fn dialog_text_note_and_labels_read_on_the_panel() {
    let _g = serial();
    let all = reads();
    let off = State { disabled: true, ..State::default() };
    let each = all.iter().map(|(r, _)| (r, State::default()));
    let each = each.chain(all.iter().filter(|(_, o)| *o).map(|(r, _)| (r, off)));
    let mut fails = Vec::new();
    per_theme(|theme| {
        for (read, st) in each.clone() {
            let r = reach(read, st, roles().bg.argb());
            if !(if st.disabled { r > NONE } else { r >= read.floor }) {
                fails.push(format!("{theme}: {} {st:?} {r:.2}:1", read.what));
            }
        }
    });
    assert!(fails.is_empty(), "{} cases\n{}", fails.len(), fails.join("\n"));
}
