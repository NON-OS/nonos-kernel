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
//! Which roles may carry alpha, checked against what they actually carry.

use crate::roles_tests::every_theme;

/* An Opaque role is painted without blending, so it must arrive at full alpha;
 * a wash, edge, ring, shadow or scrim that came out opaque would hide what it
 * sits over. Guards the split in docs/userland/design-system/colours.md "Colour types". */
#[test]
fn opaque_roles_are_opaque_and_washes_are_not() {
    let mut fails = Vec::new();
    for (name, r) in every_theme() {
        let opaque = [
            ("bg", r.bg), ("sunken", r.sunken), ("surface", r.surface), ("inset", r.inset),
            ("raised", r.raised), ("border", r.border), ("border_soft", r.border_soft),
            ("border_strong", r.border_strong), ("text", r.text), ("text_2", r.text_2),
            ("muted", r.muted), ("quiet", r.quiet), ("disabled", r.disabled),
            ("accent", r.accent), ("accent_text", r.accent_text), ("on_accent", r.on_accent),
            ("ok", r.ok), ("warn", r.warn), ("danger", r.danger), ("warn_soft", r.warn_soft),
        ];
        for (role, c) in opaque {
            let a = c.argb() >> 24;
            if a != 0xFF {
                fails.push(format!("{name}: {role} has alpha {a:#04X}, wants 0xFF"));
            }
        }
        let washes = [
            ("accent_wash", r.accent_wash), ("accent_edge", r.accent_edge),
            ("focus_ring", r.focus_ring), ("hover_wash", r.hover_wash),
            ("shadow", r.shadow), ("scrim", r.scrim),
        ];
        for (role, c) in washes {
            let a = c.argb() >> 24;
            if a >= 0xFF {
                fails.push(format!("{name}: {role} has alpha {a:#04X}, wants under 0xFF"));
            }
        }
    }
    assert!(fails.is_empty(), "\n{}", fails.join("\n"));
}
