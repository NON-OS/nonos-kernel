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

use alloc::vec::Vec;

use nonos_toolkit::font::ttf;

use super::face::Face;
use super::FONTS;

/// The page faces of a tab out of view. Layout and painting read the
/// registry, which holds the faces of the tab being worked on; a tab's own
/// are swapped in while it steps and out again after, so one tab's
/// navigation never clears another's faces.
#[derive(Default)]
pub struct Faces(Vec<Face>);

/// Exchange the registry's faces with `faces`.
pub fn swap_faces(faces: &mut Faces) {
    core::mem::swap(&mut *FONTS.lock(), &mut faces.0);
}

/* The glyph cache knows a face by the address of its data, which a later
 * face may be given once these are freed, so it is emptied first. */
impl Drop for Faces {
    fn drop(&mut self) {
        if !self.0.is_empty() {
            ttf::clear_glyph_cache();
        }
    }
}
