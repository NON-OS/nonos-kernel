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

const DOCK_W: u32 = 60;
const MENU_H: u32 = 34;
const DOCK_H: u32 = 64;
const EDGE_THRESHOLD: i32 = 20;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SnapZone {
    None = 0,
    Left = 1,
    Right = 2,
    Top = 3,
    TopLeft = 4,
    TopRight = 5,
    BottomLeft = 6,
    BottomRight = 7,
    LeftThird = 8,
    CenterThird = 9,
    RightThird = 10,
    LeftTwoThirds = 11,
    RightTwoThirds = 12,
}

pub fn detect_zone(mx: i32, my: i32, sw: u32, sh: u32) -> SnapZone {
    let left_edge = mx <= DOCK_W as i32 + EDGE_THRESHOLD;
    let right_edge = mx >= sw as i32 - EDGE_THRESHOLD;
    let top_edge = my <= MENU_H as i32 + EDGE_THRESHOLD;
    let bottom_edge = my >= sh as i32 - DOCK_H as i32 - EDGE_THRESHOLD;
    if left_edge && top_edge { return SnapZone::TopLeft; }
    if right_edge && top_edge { return SnapZone::TopRight; }
    if left_edge && bottom_edge { return SnapZone::BottomLeft; }
    if right_edge && bottom_edge { return SnapZone::BottomRight; }
    if top_edge { return SnapZone::Top; }
    if left_edge { return SnapZone::Left; }
    if right_edge { return SnapZone::Right; }
    SnapZone::None
}

pub fn zone_rect(zone: SnapZone, sw: u32, sh: u32) -> (i32, i32, u32, u32) {
    let uw = sw - DOCK_W;
    let uh = sh - MENU_H - DOCK_H;
    let half_w = uw / 2;
    let half_h = uh / 2;
    let third_w = uw / 3;
    let ox = DOCK_W as i32;
    let oy = MENU_H as i32;
    match zone {
        SnapZone::Left => (ox, oy, half_w, uh),
        SnapZone::Right => (ox + half_w as i32, oy, half_w, uh),
        SnapZone::Top => (ox, oy, uw, uh),
        SnapZone::TopLeft => (ox, oy, half_w, half_h),
        SnapZone::TopRight => (ox + half_w as i32, oy, half_w, half_h),
        SnapZone::BottomLeft => (ox, oy + half_h as i32, half_w, half_h),
        SnapZone::BottomRight => (ox + half_w as i32, oy + half_h as i32, half_w, half_h),
        SnapZone::LeftThird => (ox, oy, third_w, uh),
        SnapZone::CenterThird => (ox + third_w as i32, oy, third_w, uh),
        SnapZone::RightThird => (ox + (third_w * 2) as i32, oy, third_w, uh),
        SnapZone::LeftTwoThirds => (ox, oy, third_w * 2, uh),
        SnapZone::RightTwoThirds => (ox + third_w as i32, oy, third_w * 2, uh),
        SnapZone::None => (0, 0, 0, 0),
    }
}
