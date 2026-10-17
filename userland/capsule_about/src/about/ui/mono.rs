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

//! What the shared text helpers leave to the app: the mono face, which they do
//! not draw or measure, and bytes as the `&str` they take.

use alloc::string::String;

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::paint::measure_ttf_mono;
use nonos_toolkit::theme::Opaque;
use nonos_toolkit::widgets::text::truncate_by;

/// The bytes as text, or nothing when they are not UTF-8.
pub fn valid(bytes: &[u8]) -> &str {
    core::str::from_utf8(bytes).unwrap_or("")
}

/// One line in the mono face, with `top` the top of the line box. Returns the
/// pen x after the last glyph.
pub fn mono(fb: &mut PaintBuffer, x: u32, top: i32, bytes: &[u8], ink: Opaque, px: f32) -> i32 {
    fb.text_ttf_mono(x as i32, top, valid(bytes), ink.argb(), px)
}

/// The advance width of a run in the mono face. A column laid out from
/// proportional advances would sit left of the mono cells it is meant to align
/// with.
pub fn width_of_mono(bytes: &[u8], px: f32) -> u32 {
    measure_ttf_mono(valid(bytes), px).max(0) as u32
}

/// `text::truncate` measured in the mono face, so a hex address cut to its
/// card is cut against the advance it is drawn with.
pub fn truncate_mono(bytes: &[u8], max_w: u32, px: f32) -> String {
    let max_w = i32::try_from(max_w).unwrap_or(i32::MAX);
    truncate_by(valid(bytes), max_w, |t| measure_ttf_mono(t, px))
}
