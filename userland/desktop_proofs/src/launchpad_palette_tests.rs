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

//! Everything the Launchpad writes reads on its wash in every scheme the OS
//! offers, high contrast included: the title and tile labels, the hints, the
//! query, the caret and the page dots, on the wash and on the search pill.

use crate::palette_contrast::{every_palette, over, ratio, BODY, LARGE};

#[test]
fn launchpad_inks_read_on_its_wash_and_search_pill() {
    for (name, p) in every_palette() {
        let grounds = [("wash", p.launchpad), ("search pill", over(p.launchpad, p.tile_fill))];
        let inks = [
            ("text", p.text, BODY),
            ("text_dim", p.text_dim, BODY),
            ("the caret and the current dot in accent", p.accent, LARGE),
        ];
        for (ink_name, ink, floor) in inks {
            for (ground_name, ground) in grounds {
                let r = ratio(ink, ground);
                assert!(r >= floor, "{name}: {ink_name} on the {ground_name} is {r:.2}:1");
            }
        }
    }
}

/* The wash is painted with `fill_rect`, which writes rather than blends. */
#[test]
fn the_launchpad_wash_is_opaque_in_every_scheme() {
    for (name, p) in every_palette() {
        assert_eq!(p.launchpad >> 24, 0xFF, "{name}: the Launchpad wash is see-through");
    }
}
