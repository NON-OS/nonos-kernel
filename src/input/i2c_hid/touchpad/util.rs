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

pub fn apply_acceleration(delta: i32, acceleration: i32, sensitivity: i32) -> i32 {
    let abs_delta = delta.abs();

    let factor = if abs_delta > 50 {
        acceleration * 3
    } else if abs_delta > 20 {
        acceleration * 2
    } else if abs_delta > 5 {
        acceleration
    } else {
        1
    };

    (delta * factor * sensitivity) / 10
}

pub fn distance(x1: i32, y1: i32, x2: i32, y2: i32) -> i32 {
    let dx = x2 - x1;
    let dy = y2 - y1;
    let sum = (dx * dx + dy * dy) as u32;
    isqrt(sum) as i32
}

pub fn isqrt(n: u32) -> u32 {
    if n == 0 {
        return 0;
    }
    let mut x = n;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

pub fn timestamp() -> u64 {
    crate::arch::x86_64::time::tsc::elapsed_us()
}
