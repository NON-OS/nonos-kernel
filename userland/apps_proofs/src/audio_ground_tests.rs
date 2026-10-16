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

//! The two ambient glows on the audio player's window ground. Their strength
//! was worked out as `fall * peak / 10_000 / 100`, which is 0 for any peak
//! under 100, so both glows mixed nothing in and the ground was flat.

use crate::audio_ui::shell::ground::radial;

const BASE: u32 = 0x00_0000;
const TINT: u32 = 0xFF_FFFF;

/// The window's two glows, as `Ground::build` asks for them.
const GLOWS: [(i64, i64, u32); 2] = [(550, 310, 16), (380, 260, 14)];

#[test]
fn each_glow_shows_its_peak_at_its_centre() {
    for (rx, ry, peak) in GLOWS {
        let c = radial(BASE, TINT, 0, 0, rx, ry, peak);
        assert_ne!(c, BASE, "the {peak}% glow mixes nothing in at its centre");
        assert_eq!(c & 0xFF, peak * 255 / 100);
    }
}

#[test]
fn each_glow_fades_towards_its_rim() {
    for (rx, ry, peak) in GLOWS {
        let centre = radial(BASE, TINT, 0, 0, rx, ry, peak) & 0xFF;
        let half = radial(BASE, TINT, rx / 2, 0, rx, ry, peak) & 0xFF;
        assert!(0 < half && half < centre, "{half} halfway out, {centre} at the centre");
    }
}

#[test]
fn each_glow_leaves_the_ground_alone_at_and_past_its_rim() {
    for (rx, ry, peak) in GLOWS {
        assert_eq!(radial(BASE, TINT, rx, 0, rx, ry, peak), BASE);
        assert_eq!(radial(BASE, TINT, 0, -ry, rx, ry, peak), BASE);
        assert_eq!(radial(BASE, TINT, rx * 2, ry * 2, rx, ry, peak), BASE);
    }
}

#[test]
fn a_full_peak_is_the_tint_and_never_wraps() {
    assert_eq!(radial(BASE, TINT, 0, 0, 550, 310, 100), TINT);
    assert_eq!(radial(BASE, TINT, 0, 0, 550, 310, 400), TINT);
}
