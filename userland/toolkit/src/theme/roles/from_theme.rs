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
use super::super::legible::{ACCENT_TEXT_TARGET, MUTED_TARGET, QUIET_TARGET, VALUE_TARGET};
use super::super::legible_walk::walk_on;
use super::super::store::Theme;
use super::fixed::fixed;
use super::grounds::{flat_grounds, state_grounds, StateGrounds};
use super::light::is_light;
use super::on_accent::on_accent;
use super::status::status;
use super::table::Roles;

/// The roles a theme's seeds work out to. Pure, so the proofs can check every
/// scheme.
pub fn from_theme(t: &Theme) -> Roles {
    let (bg, surface, accent) = (t.background_argb, t.surface_argb, t.accent_argb);
    let (text, border) = (t.text_argb, t.border_argb);
    let light = is_light(bg, text);
    let f = fixed(light);
    let flat @ [_, sunken, _, raised] = flat_grounds(bg, surface, accent);
    let StateGrounds { accent_wash, hover_wash, all: grounds } = state_grounds(flat, accent, text);
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
        accent_text: Opaque::new(walk_on(text, accent, &grounds, ACCENT_TEXT_TARGET, BODY)),
        on_accent: Opaque::new(on_accent(accent, bg, text)),
        accent_wash: Translucent::new(accent_wash),
        accent_edge: Translucent::new(with_alpha(accent, 0x59)),
        focus_ring: Translucent::new(with_alpha(accent, 0x80)),
        hover_wash: Translucent::new(hover_wash),
        ok: status(f.ok, light, &grounds),
        warn: status(f.warn, light, &grounds),
        danger: status(f.danger, light, &grounds),
        warn_soft: f.warn_soft,
        shadow: f.shadow,
        scrim: f.scrim,
    }
}
