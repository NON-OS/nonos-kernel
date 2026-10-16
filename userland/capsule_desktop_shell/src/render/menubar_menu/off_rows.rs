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

/*
 * The menu rows that open an app setup can turn off, as the dispatcher in
 * server/handlers/menubar_action.rs maps them. A row whose app is off is
 * drawn dim, and the dispatcher opens nothing for it.
 */

use crate::apps_off::is_off;
use crate::render::palette::ShellPalette;

fn service(title: usize, row: usize) -> Option<&'static [u8]> {
    match (title, row) {
        (1, 2) => Some(b"app.file_manager"),
        (3, 1) => Some(b"app.browser"),
        _ => None,
    }
}

/* The colour a row's label is drawn in. */
pub(super) fn row_fg(p: &ShellPalette, title: usize, row: usize) -> u32 {
    match service(title, row) {
        Some(s) if is_off(s) => p.text_muted,
        _ => p.text,
    }
}
