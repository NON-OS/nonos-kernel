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

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::roles;

use super::entries::Entry;
use super::file_kind::kind_of;
use super::fmt_time::fmt_time;
use super::human_size::human_size;
use super::list_cols::Cols;
use super::list_kind_label::kind_label;
use super::measure_text::right_text;

const META_PX: f32 = 14.0;
const TEXT_DY: u32 = 15;

/// The three right-aligned meta cells. Every cell right-aligns on its own
/// column's end, the same edge `list_head` set its label against. No row menu
/// is drawn: the capsule has none to open.
pub fn row_meta(fb: &mut PaintBuffer, entry: &Entry, y: u32, c: &Cols) {
    let (ty, muted) = (y + TEXT_DY, roles().muted.argb());
    right_text(fb, c.cols[1].x + c.cols[1].w, ty, kind_label(kind_of(entry)), META_PX, muted);
    if let Some(size) = entry.size {
        right_text(fb, c.cols[2].x + c.cols[2].w, ty, &human_size(size), META_PX, muted);
    }
    if entry.mtime != 0 {
        right_text(fb, c.cols[3].x + c.cols[3].w, ty, &fmt_time(entry.mtime), META_PX, muted);
    }
}
