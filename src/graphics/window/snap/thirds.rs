// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::zones::SnapZone;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SnapThird {
    Left,
    Center,
    Right,
    LeftTwo,
    RightTwo,
}

impl SnapThird {
    pub fn to_zone(self) -> SnapZone {
        match self {
            Self::Left => SnapZone::LeftThird,
            Self::Center => SnapZone::CenterThird,
            Self::Right => SnapZone::RightThird,
            Self::LeftTwo => SnapZone::LeftTwoThirds,
            Self::RightTwo => SnapZone::RightTwoThirds,
        }
    }
}

pub fn snap_to_third(third: SnapThird, sw: u32, sh: u32) -> (i32, i32, u32, u32) {
    super::zones::zone_rect(third.to_zone(), sw, sh)
}

pub fn detect_third_from_key(key: u8, ctrl: bool, alt: bool) -> Option<SnapThird> {
    if !ctrl || !alt {
        return None;
    }
    match key {
        b'1' => Some(SnapThird::Left),
        b'2' => Some(SnapThird::Center),
        b'3' => Some(SnapThird::Right),
        b'4' => Some(SnapThird::LeftTwo),
        b'5' => Some(SnapThird::RightTwo),
        _ => None,
    }
}

pub fn cycle_thirds(current: SnapZone, direction: i8) -> SnapZone {
    let thirds = [SnapZone::LeftThird, SnapZone::CenterThird, SnapZone::RightThird];
    let idx = thirds.iter().position(|&z| z == current);
    match idx {
        Some(i) => {
            let new_idx = ((i as i8 + direction).rem_euclid(3)) as usize;
            thirds[new_idx]
        }
        None => SnapZone::LeftThird,
    }
}
