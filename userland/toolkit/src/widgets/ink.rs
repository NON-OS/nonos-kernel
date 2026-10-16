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

//! Colour names a widget takes in place of raw colours.

use crate::theme::{Opaque, Roles};

/// What an app names instead of a colour. Each variant is the theme role of
/// the same name, but for `Accent`, which is `accent_text`: the accent as text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Ink {
    Text,
    Text2,
    Muted,
    Quiet,
    Accent,
    Ok,
    Warn,
    Danger,
}

impl Ink {
    /// The colour this ink takes in the given roles.
    pub fn colour(self, r: &Roles) -> Opaque {
        match self {
            Ink::Text => r.text,
            Ink::Text2 => r.text_2,
            Ink::Muted => r.muted,
            Ink::Quiet => r.quiet,
            Ink::Accent => r.accent_text,
            Ink::Ok => r.ok,
            Ink::Warn => r.warn,
            Ink::Danger => r.danger,
        }
    }
}

/// The status a pill or bar shows. Plain is the muted role and Accent is
/// `accent_text`, since a pill draws it as text and a dot; the rest are the
/// theme roles of the same name. A bar fills in the raw accent instead.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Tone {
    #[default]
    Plain,
    Accent,
    Ok,
    Warn,
    Danger,
}

impl Tone {
    /// The colour this tone takes in the given roles.
    pub fn colour(self, r: &Roles) -> Opaque {
        match self {
            Tone::Plain => r.muted,
            Tone::Accent => r.accent_text,
            Tone::Ok => r.ok,
            Tone::Warn => r.warn,
            Tone::Danger => r.danger,
        }
    }
}
