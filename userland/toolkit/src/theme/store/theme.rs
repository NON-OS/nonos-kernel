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
use super::super::legible::{muted, quiet, MUTED_TARGET, QUIET_TARGET};

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Theme {
    pub background_argb: u32,
    pub surface_argb: u32,
    pub accent_argb: u32,
    pub text_argb: u32,
    pub border_argb: u32,
    /*
     * Derived from the five above rather than chosen: secondary and placeholder text,
     * muted as far as the scheme's contrast allows. They are in the snapshot because
     * they are read per glyph run and computing them there would put a contrast
     * search in the paint path. `from_roles` is the only thing that fills them in,
     * so build a theme through it rather than with a struct literal.
     */
    pub muted_argb: u32,
    pub quiet_argb: u32,
    pub revision: u32,
}

impl Theme {
    /*
     * The one place the derived roles are computed. Two callers build a theme from
     * five colours: the settings translation and the IPC apply. Deriving in each
     * would be two answers to one question, and the one that drifted would be the
     * one nobody was looking at.
     */
    pub fn from_roles(bg: u32, surface: u32, accent: u32, text: u32, border: u32) -> Self {
        Self {
            background_argb: bg,
            surface_argb: surface,
            accent_argb: accent,
            text_argb: text,
            border_argb: border,
            muted_argb: muted(text, bg, surface, MUTED_TARGET),
            quiet_argb: quiet(text, bg, surface, QUIET_TARGET),
            // Assigned by the store when it takes the theme, not by whoever builds one.
            revision: 0,
        }
    }
}
