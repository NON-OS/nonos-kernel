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
//! The contrast floors the derived colour roles have to clear.

use crate::theme::roles::{from_theme, Roles};
use crate::theme::select::theme_of;
use crate::wcag::{ratio, BODY, LARGE};
use nonos_policy_proto::theme_labels::THEME_LABELS;

/// Every scheme in the picker, then the high-contrast override, with its roles.
pub(crate) fn every_theme() -> Vec<(String, Roles)> {
    let mut all: Vec<(String, Roles)> = (0..THEME_LABELS.len())
        .map(|i| {
            let name = core::str::from_utf8(THEME_LABELS[i]).unwrap_or("?");
            (name.to_string(), from_theme(&theme_of(i as u8, false)))
        })
        .collect();
    all.push(("high contrast".to_string(), from_theme(&theme_of(0, true))));
    all
}

fn check(fails: &mut Vec<String>, theme: &str, pair: (&str, u32, &str, u32), floor: f64) {
    let (role, ink, where_, ground) = pair;
    let r = ratio(ink, ground);
    if r < floor {
        fails.push(format!("{theme}: {role} on {where_} is {r:.3}:1, under {floor}"));
    }
}

/* Body copy, secondary copy and captions must read on every ground a widget puts
 * them on, and so must a label on a filled accent button. The 4.5:1 floor from
 * docs/userland/design-system/colours.md "Readability". */
#[test]
fn body_inks_hold_the_body_floor() {
    let mut fails = Vec::new();
    for (name, r) in every_theme() {
        for (role, ink) in [("text", r.text), ("text_2", r.text_2), ("muted", r.muted)] {
            let grounds = [("bg", r.bg), ("surface", r.surface), ("sunken", r.sunken)];
            for (where_, ground) in grounds.into_iter().chain([("raised", r.raised)]) {
                check(&mut fails, &name, (role, ink.argb(), where_, ground.argb()), BODY);
            }
        }
        let pair = ("on_accent", r.on_accent.argb(), "accent", r.accent.argb());
        check(&mut fails, &name, pair, BODY);
    }
    assert!(fails.is_empty(), "\n{}", fails.join("\n"));
}

/* Placeholders on all four grounds, and the bare accent (links, selected marks) on
 * bg, are held to the 3:1 large-text and non-text floor, per colours.md "Readability". */
#[test]
fn quiet_inks_hold_the_large_floor() {
    let mut fails = Vec::new();
    for (name, r) in every_theme() {
        let grounds = [("bg", r.bg), ("sunken", r.sunken), ("surface", r.surface)];
        for (where_, ground) in grounds.into_iter().chain([("raised", r.raised)]) {
            check(&mut fails, &name, ("quiet", r.quiet.argb(), where_, ground.argb()), LARGE);
        }
        check(&mut fails, &name, ("accent", r.accent.argb(), "bg", r.bg.argb()), LARGE);
    }
    assert!(fails.is_empty(), "\n{}", fails.join("\n"));
}
