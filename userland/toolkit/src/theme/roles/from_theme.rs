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

//! Working the roles out from a theme's seeds.

use super::super::colour::{Opaque, Translucent};
use super::super::contrast::{BODY, LARGE};
use super::super::derive::{mix, with_alpha};
use super::super::legible::{MUTED_TARGET, QUIET_TARGET};
use super::super::legible_walk::walk_on;
use super::super::store::{snapshot, Theme};
use super::fixed::fixed;
use super::light::is_light;
use super::on_accent::on_accent;
use super::table::Roles;

const BLACK: u32 = 0xFF00_0000;
/// How far `text_2` steps towards the ground when the scheme can spare it.
const VALUE_TARGET: u8 = 36;

/// The roles for the theme in force in this process.
pub fn roles() -> Roles {
    from_theme(&snapshot())
}

/// The roles a theme's seeds work out to. Pure, so the proofs can check every
/// scheme.
pub fn from_theme(t: &Theme) -> Roles {
    let (bg, surface, accent) = (t.background_argb, t.surface_argb, t.accent_argb);
    let (text, border) = (t.text_argb, t.border_argb);
    let f = fixed(is_light(bg, text));
    let (sunken, raised) = (mix(bg, BLACK, 12), mix(surface, accent, 11));
    let grounds = [bg, sunken, surface, raised];
    Roles {
        bg: Opaque::new(bg),
        sunken: Opaque::new(sunken),
        surface: Opaque::new(surface),
        inset: Opaque::new(mix(bg, surface, 128)),
        raised: Opaque::new(raised),
        border: Opaque::new(border),
        border_soft: Opaque::new(mix(bg, border, 87)),
        border_strong: Opaque::new(mix(border, text, 16)),
        text: Opaque::new(text),
        text_2: Opaque::new(walk_on(text, bg, &grounds, VALUE_TARGET, BODY)),
        muted: Opaque::new(walk_on(text, bg, &grounds, MUTED_TARGET, BODY)),
        quiet: Opaque::new(walk_on(text, bg, &grounds, QUIET_TARGET, LARGE)),
        disabled: Opaque::new(mix(border, text, 57)),
        accent: Opaque::new(accent),
        accent_text: Opaque::new(mix(accent, text, 146)),
        on_accent: Opaque::new(on_accent(accent, bg, text)),
        accent_wash: Translucent::new(with_alpha(accent, 0x20)),
        accent_edge: Translucent::new(with_alpha(accent, 0x59)),
        focus_ring: Translucent::new(with_alpha(accent, 0x80)),
        hover_wash: Translucent::new(with_alpha(text, 0x14)),
        ok: f.ok,
        warn: f.warn,
        danger: f.danger,
        warn_soft: f.warn_soft,
        shadow: f.shadow,
        scrim: f.scrim,
    }
}
