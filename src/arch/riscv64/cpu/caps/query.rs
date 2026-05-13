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

use core::sync::atomic::Ordering;

use super::bits::{CAP_A, CAP_C, CAP_CONFIGURED, CAP_D, CAP_F, CAP_V};
use super::state::CAPS;

#[inline]
fn read() -> u16 {
    CAPS.load(Ordering::Acquire)
}

#[inline]
pub fn is_configured() -> bool {
    read() & CAP_CONFIGURED != 0
}

#[inline]
pub fn has_f() -> bool {
    read() & CAP_F != 0
}

#[inline]
pub fn has_d() -> bool {
    read() & CAP_D != 0
}

#[inline]
pub fn has_v() -> bool {
    read() & CAP_V != 0
}

#[inline]
pub fn has_a() -> bool {
    read() & CAP_A != 0
}

#[inline]
pub fn has_c() -> bool {
    read() & CAP_C != 0
}
