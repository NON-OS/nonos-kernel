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

//! Working the shell's colours out from the theme's roles.

use nonos_toolkit::theme::contrast::{BODY, LARGE};
use nonos_toolkit::theme::derive::with_alpha;
use nonos_toolkit::theme::{roles, Opaque, Roles};

use super::alpha;
use super::glass::glass;
use super::prompt::Prompt;
use super::table::ShellPalette;

/// The shell's colours for the theme in force in this process.
pub fn current() -> ShellPalette {
    from_roles(&roles())
}

/// The shell's colours for a theme's roles. Pure, so the proofs can check every
/// scheme.
pub fn from_roles(r: &Roles) -> ShellPalette {
    let at = |c: Opaque, a: u8| with_alpha(c.argb(), a);
    let inks = [(r.text, BODY), (r.muted, BODY), (r.quiet, LARGE)];
    ShellPalette {
        panel: glass(r.surface, alpha::PANEL, &inks),
        bar: glass(r.sunken, alpha::BAR, &inks),
        dock: at(r.surface, alpha::DOCK),
        line: at(r.accent, alpha::LINE),
        line_soft: at(r.accent, alpha::LINE_SOFT),
        line_hard: at(r.accent, alpha::LINE_HARD),
        accent: r.accent.argb(),
        accent_dim: at(r.accent, alpha::ACCENT_DIM),
        accent_hover: at(r.accent, alpha::ACCENT_HOVER),
        text: r.text.argb(),
        text_dim: r.muted.argb(),
        text_muted: r.quiet.argb(),
        negative: r.danger.argb(),
        positive: r.ok.argb(),
        warn: r.warn.argb(),
        pill_edit: glass(r.raised, alpha::PILL_EDIT, &[(r.text, BODY)]),
        icon_scrim: at(r.bg, alpha::ICON_SCRIM),
        tile_active: at(r.accent, alpha::TILE_ACTIVE),
        tile_pulse: at(r.warn, alpha::TILE_PULSE),
        tile_open: at(r.accent, alpha::TILE_OPEN),
        tile_fill: at(r.accent, alpha::TILE_FILL),
        tile_off: at(r.quiet, alpha::TILE_OFF),
        launchpad: r.bg.argb(),
        prompt: Prompt::from_roles(r),
    }
}
