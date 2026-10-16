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

extern crate alloc;

use alloc::string::{String, ToString};

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::roles;

use super::chrome_card::Plate;
use super::entries::Entry;
use super::file_color::color;
use super::file_kind::kind_of;
use super::human_size::human_size;
use super::icon;
use super::list_kind_label::kind_label;
use super::measure_text::{truncate_to_width, width_of};

const GLYPH: u32 = 44;
const GLYPH_DY: u32 = 10;
const NAME_PX: f32 = 14.0;
const META_PX: f32 = 13.0;

/// One grid card on the shared plate: a large typed glyph, the measured name,
/// and a meta line. This capsule has no image or PDF decoder, so a card shows
/// its filetype glyph rather than faking a preview. The menu affordance is
/// dimmed: there is no card menu behind it yet.
pub fn card(fb: &mut PaintBuffer, entry: &Entry, x: u32, y: u32, w: u32, h: u32, lit: bool) {
    let r = roles();
    let bg = if lit { r.raised.argb() } else { r.surface.argb() };
    let plate = Plate::new(bg).tint();
    let plate = if lit { plate.line(r.accent_edge.argb()).glow(3) } else { plate };
    plate.draw(fb, x, y, w, h);
    let tint = color(kind_of(entry));
    let (gx, gy) = (x + w.saturating_sub(GLYPH) / 2, y + GLYPH_DY);
    if entry.is_dir {
        icon::folder(fb, gx, gy, GLYPH, tint, bg);
    } else {
        icon::file(fb, gx, gy, GLYPH, tint, bg);
    }
    let name = truncate_to_width(fb, entry.label.trim_end_matches('/'), NAME_PX, w.saturating_sub(16));
    let nx = x + w.saturating_sub(width_of(fb, name, NAME_PX)) / 2;
    let ink = if lit { r.text } else { r.text_2 }.argb();
    let _ = fb.text_ttf(nx as i32, (gy + GLYPH + 4) as i32, name, ink, NAME_PX);
    let meta = meta_line(entry);
    let mx = x + w.saturating_sub(width_of(fb, &meta, META_PX)) / 2;
    let _ = fb.text_ttf(mx as i32, (gy + GLYPH + 26) as i32, &meta, r.muted.argb(), META_PX);
}

/// A file's size where the walk reported one, and its kind otherwise, so the
/// line under a name is never blank.
fn meta_line(entry: &Entry) -> String {
    match entry.size {
        Some(size) if !entry.is_dir => human_size(size),
        _ => kind_label(kind_of(entry)).to_string(),
    }
}
