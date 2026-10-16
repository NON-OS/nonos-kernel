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

//! The roles for the theme in force, worked out once for each theme.

use spin::Mutex;

use super::super::store::{snapshot, Theme};
use super::from_theme::from_theme;
use super::table::Roles;

/// The theme the roles were last worked out for, and those roles.
static LAST: Mutex<Option<(Theme, Roles)>> = Mutex::new(None);

/// The roles for the theme in force in this process. Working them out walks
/// every ink over sixteen grounds, and a widget asks on every draw, so they are
/// kept until the theme in the store differs from the one they came from.
pub fn roles() -> Roles {
    let theme = snapshot();
    let mut last = LAST.lock();
    match *last {
        Some((seen, r)) if seen == theme => r,
        _ => {
            let r = from_theme(&theme);
            *last = Some((theme, r));
            r
        }
    }
}
