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

//! The System theme: the editor palette worked out from the OS theme's roles.
//!
//! The roles carry no syntax hues, so each token takes a status ink or a mix of
//! inks that already clear 4.5:1 on the ground. Every mix here was measured on
//! the ground and on the current-line band in all nine schemes and in high
//! contrast; Solarized's own text clears only 3.98:1 on the selection.

use nonos_toolkit::theme::derive::mix;
use nonos_toolkit::theme::Roles;

use super::fields::Theme;

/// How far a selected row moves from the rail towards the accent, out of 255.
pub const SELECT_WASH: u8 = 40;
const CURRENT_LINE: u8 = 12;
const SELECTION: u8 = 64;

pub(super) fn from_roles(r: &Roles) -> Theme {
    let (bg, sunken, text, accent) = (r.bg.argb(), r.sunken.argb(), r.text.argb(), r.accent.argb());
    let (warn, accent_text) = (r.warn.argb(), r.accent_text.argb());
    Theme {
        background: bg,
        foreground: text,
        title: text,
        muted: r.muted.argb(),
        disabled: r.disabled.argb(),
        header_bg: sunken,
        activity_bg: sunken,
        sidebar_bg: sunken,
        tabbar_bg: sunken,
        tab_active_bg: bg,
        tab_inactive_bg: r.surface.argb(),
        row_select: mix(sunken, accent, SELECT_WASH),
        icon: r.quiet.argb(),
        icon_active: text,
        folder: accent,
        gutter_bg: sunken,
        gutter_fg: r.quiet.argb(),
        gutter_cur: text,
        line: r.border.argb(),
        accent,
        caret: accent,
        current_line: mix(bg, text, CURRENT_LINE),
        selection: mix(bg, accent, SELECTION),
        syn_keyword: mix(r.danger.argb(), accent_text, 128),
        syn_string: r.ok.argb(),
        syn_comment: r.muted.argb(),
        syn_number: warn,
        syn_type: mix(warn, text, 96),
        syn_function: mix(accent_text, text, 64),
    }
}
