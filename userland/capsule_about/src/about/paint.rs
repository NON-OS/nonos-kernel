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

use super::lines::{
    ABI_LABEL, ABI_VALUE, COPYRIGHT, HINT_LINE, LICENSE, PRODUCT, TAGLINE, VERSION_LABEL,
    VERSION_VALUE,
};
use super::state::State;
use super::theme::{ACCENT, BACKGROUND, BODY, HEADLINE, HINT};

const TOP_BAND_HEIGHT: u32 = 56;
const TEXT_LEFT: u32 = 24;
const LINE_HEIGHT: u32 = 22;
const FIRST_LINE_Y: u32 = TOP_BAND_HEIGHT + 24;

pub fn paint(state: &mut State, fb: &mut PaintBuffer) {
    fb.clear(BACKGROUND);
    fb.fill_rect(0, 0, fb.width, TOP_BAND_HEIGHT, ACCENT);
    fb.text(TEXT_LEFT, 20, PRODUCT, HEADLINE);
    let mut y = FIRST_LINE_Y;
    fb.text(TEXT_LEFT, y, TAGLINE, HEADLINE);
    y += LINE_HEIGHT * 2;
    fb.text(TEXT_LEFT, y, VERSION_LABEL, BODY);
    fb.text(TEXT_LEFT + 96, y, VERSION_VALUE, HEADLINE);
    y += LINE_HEIGHT;
    fb.text(TEXT_LEFT, y, ABI_LABEL, BODY);
    fb.text(TEXT_LEFT + 96, y, ABI_VALUE, HEADLINE);
    y += LINE_HEIGHT * 2;
    fb.text(TEXT_LEFT, y, COPYRIGHT, BODY);
    y += LINE_HEIGHT;
    fb.text(TEXT_LEFT, y, LICENSE, BODY);
    fb.text(TEXT_LEFT, fb.height - 32, HINT_LINE, HINT);
    state.painted = true;
}
