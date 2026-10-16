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

//! The shell's text reads on its menu panel and its top bar, and a rename on
//! its pill, in every scheme the OS offers, high contrast included,
//! with black or white showing through.

use crate::palette_contrast::{every_palette, over, ratio, BEHIND, BODY, LARGE};

#[test]
fn shell_text_reads_on_its_glass_over_any_wallpaper() {
    for (name, p) in every_palette() {
        let grounds = [("panel", p.panel), ("bar", p.bar)];
        let inks = [("text", p.text, BODY), ("text_dim", p.text_dim, BODY)];
        let inks = inks.into_iter().chain([("text_muted", p.text_muted, LARGE)]);
        for (ink_name, ink, floor) in inks {
            for (ground_name, ground) in grounds {
                for (behind_name, behind) in BEHIND {
                    let r = ratio(ink, over(behind, ground));
                    let at = format!("{name}: {ink_name} on {ground_name} over {behind_name}");
                    assert!(r >= floor, "{at} is {r:.2}:1");
                }
            }
        }
    }
}

#[test]
fn a_rename_reads_on_its_pill_over_any_wallpaper() {
    for (name, p) in every_palette() {
        for (behind_name, behind) in BEHIND {
            let r = ratio(p.text, over(behind, p.pill_edit));
            assert!(r >= BODY, "{name}: text on the rename pill over {behind_name} is {r:.2}:1");
        }
    }
}

/* The glass is made more opaque only as far as a scheme needs: the house
 * theme keeps the panel's and the bar's alpha. The dock carries no text, so
 * it keeps its own in every scheme. */
#[test]
fn the_house_theme_keeps_its_glass() {
    let p = &every_palette()[0].1;
    assert_eq!([p.panel >> 24, p.bar >> 24, p.dock >> 24], [0xE6, 0xE0, 0xB8]);
}
