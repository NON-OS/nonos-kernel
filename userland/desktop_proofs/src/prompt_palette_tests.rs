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

//! The shell's prompts read in every scheme the OS offers, high contrast
//! included: the text on the panel and each button's label on its fill. The
//! prompts paint with `fill_rect`, so every one of their colours is opaque.

use crate::palette_contrast::{every_palette, ratio, BODY};

/// The Delete button's red, kept in render/delete_prompt.rs.
const DELETE_BG: u32 = 0xFFA1_2A2A;

#[test]
fn prompt_labels_read_on_their_fills_in_every_scheme() {
    for (name, p) in every_palette() {
        let c = p.prompt;
        let pairs = [
            ("fg on panel", c.fg, c.panel),
            ("dim on panel", c.dim, c.panel),
            ("approve_fg on approve", c.approve_fg, c.approve),
            ("cancel_fg on cancel", c.cancel_fg, c.cancel),
            ("the Delete label on its red", c.ink_on(DELETE_BG), DELETE_BG),
            ("the hidden-caps warning on panel", c.warn, c.panel),
        ];
        for (pair, ink, fill) in pairs {
            let r = ratio(ink, fill);
            assert!(r >= BODY, "{name}: {pair} is {r:.2}:1");
        }
    }
}

#[test]
fn prompt_colours_are_opaque_in_every_scheme() {
    for (name, p) in every_palette() {
        let c = p.prompt;
        let all = [
            c.panel,
            c.border,
            c.fg,
            c.dim,
            c.approve,
            c.approve_fg,
            c.cancel,
            c.cancel_fg,
            c.warn,
        ];
        assert!(all.iter().all(|f| f >> 24 == 0xFF), "{name}: a prompt colour is see-through");
    }
}
