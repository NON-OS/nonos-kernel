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

//! Which theme is in force, and stepping to the next.

use core::sync::atomic::{AtomicUsize, Ordering};

use nonos_toolkit::theme::roles;

use super::fields::Theme;
use super::named::THEMES;
use super::system::from_roles;

/// System, then each fixed theme.
const CHOICES: usize = THEMES.len() + 1;

/// The choice in force, shared by every tab and paint path: 0 is System, the
/// default, and `n` is `THEMES[n - 1]`. It is not saved, so every launch starts
/// on System.
static ACTIVE: AtomicUsize = AtomicUsize::new(0);

/// The palette every painter reads from this frame. System is worked out from
/// the OS theme on every call, so it follows a change made in Settings on the
/// next paint. That takes a contrast search, so read it once per paint, not once
/// per glyph.
pub fn active() -> Theme {
    match ACTIVE.load(Ordering::Relaxed) % CHOICES {
        0 => from_roles(&roles()),
        n => THEMES[n - 1],
    }
}

/// Advance to the next choice, wrapping: System, NONOS Docs, Light, Dracula,
/// Nord, then System again. Driven by the theme button, View > Toggle Theme and
/// Ctrl+K T.
pub fn cycle() {
    ACTIVE.store((ACTIVE.load(Ordering::Relaxed) + 1) % CHOICES, Ordering::Relaxed);
}
