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

//! The choices the theme button, the palette and `theme` step through: System,
//! which follows the theme chosen in Settings and is the default, then the named
//! profiles. The saved preference is an index into this list.

use nonos_toolkit::theme::{roles, snapshot};

use super::ansi::base16_for;
use super::types::Theme;
use super::{profiles, system};

pub const SYSTEM: u16 = 0;
/// System, then each named profile.
pub const COUNT: u16 = profiles::COUNT + 1;

/// The palette for `choice` and the sixteen program colours that go with it.
/// System is worked out from the OS theme on every call, so a change made in
/// Settings shows on the next paint.
pub fn resolve(choice: u16) -> (Theme, [u32; 16]) {
    match choice.checked_sub(1) {
        None => {
            let r = roles();
            (system::theme(&r), system::ansi(&r))
        }
        Some(i) => {
            let t = *profiles::by_index(i);
            (t, *base16_for(t.bg))
        }
    }
}

/// What the program colours are taken from: the choice, and under System the
/// OS theme's revision, which moves only when Settings changes the theme.
pub fn key(choice: u16) -> (u16, u32) {
    (choice, if choice == SYSTEM { snapshot().revision } else { 0 })
}

/// The choice after `choice`: System, Dark, Dim, Light, Abyss, then System.
pub fn next(choice: u16) -> u16 {
    (choice + 1) % COUNT
}

pub fn by_name(n: &[u8]) -> Option<u16> {
    match n {
        b"system" => Some(SYSTEM),
        _ => profiles::by_name(n).map(|i| i + 1),
    }
}
