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

//! The System appearance: the chrome's palette worked out from the OS theme's
//! roles, so the Browser follows the theme chosen in Settings. Each token takes
//! the role that means the same thing. Those the roles have no name for take
//! the nearest role proven to read where the token is drawn, or the accent wash
//! laid over the ground it sits on, so every token but `shadow` is opaque.

use nonos_toolkit::paint::mixer::over;
use nonos_toolkit::theme::Roles;

use super::Palette;

/// The palette the roles `r` work out to. Pure, so the proofs can check it in
/// every scheme.
pub fn from_roles(r: &Roles) -> Palette {
    let wash = r.accent_wash.argb();
    Palette {
        ground: r.bg.argb(),
        surface: r.surface.argb(),
        sidebar: r.sunken.argb(),
        edge: r.border.argb(),
        field: r.raised.argb(),
        ink: r.text.argb(),
        ink2: r.text_2.argb(),
        muted: r.muted.argb(),
        accent: r.accent.argb(),
        accent_soft: over(r.surface.argb(), wash),
        on_accent: r.on_accent.argb(),
        sky: over(r.bg.argb(), wash),
        teal: r.ok.argb(),
        teal_soft: r.sunken.argb(),
        ok: r.ok.argb(),
        err: r.danger.argb(),
        disabled: r.quiet.argb(),
        shadow: r.shadow.argb(),
        warn: r.warn.argb(),
        warn_soft: r.warn_soft.argb(),
    }
}
