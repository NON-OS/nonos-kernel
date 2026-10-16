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

use super::chrome_glow::glow_out;

/// The two states a pill control can be in. `Active` is the only one that
/// spends the accent hue, so selection stays the one saturated thing on screen.
/// There is no hover state: the capsule does not track the pointer between
/// clicks, so nothing could ever draw one.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PillState {
    Idle,
    Active,
}

/// A pill plate with radius `r`: the controls use a squarer shoulder than a
/// true pill. Blends throughout, so it is safe over live paint.
pub fn pill_r(fb: &mut PaintBuffer, x: u32, y: u32, w: u32, h: u32, r: u32, state: PillState) {
    if w == 0 || h == 0 {
        return;
    }
    let theme = roles();
    let (fill, line) = match state {
        PillState::Idle => (theme.surface.argb(), theme.border.argb()),
        PillState::Active => (theme.accent_wash.argb(), theme.accent_edge.argb()),
    };
    if state == PillState::Active {
        glow_out(fb, x, y, w, h, r, 3);
    }
    fb.fill_round(x, y, w, h, r, fill);
    fb.stroke_round(x, y, w, h, r, 1, line);
}

/// The label colour that pairs with a pill drawn in `state`.
pub fn pill_ink(state: PillState) -> u32 {
    let r = roles();
    match state {
        PillState::Active => r.accent.argb(),
        _ => r.muted.argb(),
    }
}
