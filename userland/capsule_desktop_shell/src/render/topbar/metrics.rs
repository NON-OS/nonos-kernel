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

//! Measurements for the menu bar: where its logo, wordmark and status glyphs
//! sit, at the shell's scale. Its colours are in `render::palette`.

use crate::render::measure_aa::measure_aa_bold;
use crate::render::ui_font::{self, BRAND_PX};

pub(super) const WORDMARK_TEXT: &str = "NØNOS";

const LOGO_X_LOGICAL: u32 = 18;
const LOGO_SIZE_LOGICAL: u32 = 17;
const WORDMARK_X_LOGICAL: u32 = 44;

const RIGHT_MARGIN_LOGICAL: u32 = 18;
const PAD_X_LOGICAL: u32 = 12;
const GAP_LOGICAL: u32 = 16;

const BATT_GLYPH_W_LOGICAL: u32 = 26;
const NET_GLYPH_W_LOGICAL: u32 = 16;
const SEARCH_GLYPH_W_LOGICAL: u32 = 15;

pub(super) fn logo_x() -> u32 {
    ui_font::px(LOGO_X_LOGICAL)
}

pub(super) fn logo_size() -> u32 {
    ui_font::px(LOGO_SIZE_LOGICAL)
}

pub(super) fn wordmark_x() -> u32 {
    ui_font::px(WORDMARK_X_LOGICAL)
}

/// Right edge of the clickable brand region (logo plus wordmark). Measured from
/// the face that paints it, so the hit box tracks the drawn glyphs.
pub(crate) fn brand_right() -> u32 {
    wordmark_x() + measure_aa_bold(WORDMARK_TEXT, BRAND_PX) + pad_x()
}

pub(super) fn right_margin() -> u32 {
    ui_font::px(RIGHT_MARGIN_LOGICAL)
}

pub(super) fn pad_x() -> u32 {
    ui_font::px(PAD_X_LOGICAL)
}

pub(super) fn gap() -> u32 {
    ui_font::px(GAP_LOGICAL)
}

pub(super) fn batt_glyph_w() -> u32 {
    BATT_GLYPH_W_LOGICAL * ui_font::scale()
}

pub(super) fn net_glyph_w() -> u32 {
    NET_GLYPH_W_LOGICAL * ui_font::scale()
}

pub(super) fn search_glyph_w() -> u32 {
    SEARCH_GLYPH_W_LOGICAL * ui_font::scale()
}
