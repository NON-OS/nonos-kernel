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

//! A document run's ink, resolved against the theme when it is painted.

use super::fields::Theme;
use crate::doc::style::{INK_ACCENT, INK_HEADING};

impl Theme {
    /// The colour a run stored with `ink` paints in. The model keeps the ink,
    /// not a colour, so switching themes recolours the page without a reflow.
    pub fn ink(&self, ink: u32) -> u32 {
        match ink {
            INK_HEADING => self.folder,
            INK_ACCENT => self.accent,
            _ => self.foreground,
        }
    }
}
