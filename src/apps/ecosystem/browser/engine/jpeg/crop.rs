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

use alloc::vec::Vec;

pub(super) fn crop_plane(
    plane: &[u8],
    plane_width: usize,
    target_w: usize,
    target_h: usize,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(target_w * target_h);
    for row in 0..target_h {
        let start = row * plane_width;
        let end = start + target_w;
        if end <= plane.len() {
            out.extend_from_slice(&plane[start..end]);
        } else if start < plane.len() {
            out.extend_from_slice(&plane[start..]);
            for _ in 0..(end - plane.len()) {
                out.push(128);
            }
        } else {
            for _ in 0..target_w {
                out.push(128);
            }
        }
    }
    out
}
