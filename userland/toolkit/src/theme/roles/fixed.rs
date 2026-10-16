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

//! The roles a theme does not move: status colours, and the shadows under things.

use super::super::colour::{Opaque, Translucent};
use super::super::palette;

const WARN_SOFT_LIGHT: u32 = 0xFFFE_F3C7;
const WARN_SOFT_DARK: u32 = 0xFF3A_2A0C;
const SHADOW_LIGHT: u32 = 0x3010_1828;
const SHADOW_DARK: u32 = 0x6000_0000;
const SCRIM: u32 = 0x8C06_0A0E;

/// The fixed roles, picked for a light or a dark theme.
pub(super) struct Fixed {
    pub ok: Opaque,
    pub warn: Opaque,
    pub danger: Opaque,
    pub warn_soft: Opaque,
    pub shadow: Translucent,
    pub scrim: Translucent,
}

/// The fixed roles for a light theme when `light`, otherwise for a dark one.
pub(super) fn fixed(light: bool) -> Fixed {
    let pick = |on_light: u32, on_dark: u32| if light { on_light } else { on_dark };
    Fixed {
        ok: Opaque::new(palette::OK),
        warn: Opaque::new(palette::WARN),
        danger: Opaque::new(palette::ERROR),
        warn_soft: Opaque::new(pick(WARN_SOFT_LIGHT, WARN_SOFT_DARK)),
        shadow: Translucent::new(pick(SHADOW_LIGHT, SHADOW_DARK)),
        scrim: Translucent::new(SCRIM),
    }
}
