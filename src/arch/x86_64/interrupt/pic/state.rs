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

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use spin::Once;

pub(crate) static INITIALIZED: AtomicBool = AtomicBool::new(false);
pub(crate) static DISABLED: AtomicBool = AtomicBool::new(false);
pub(crate) static MASTER_MASK: AtomicU8 = AtomicU8::new(0xFF);
pub(crate) static SLAVE_MASK: AtomicU8 = AtomicU8::new(0xFF);
pub(crate) static MASK_SNAPSHOT: Once<(u8, u8)> = Once::new();

#[inline]
pub fn is_initialized() -> bool {
    INITIALIZED.load(Ordering::Acquire)
}

#[inline]
pub fn is_disabled() -> bool {
    DISABLED.load(Ordering::Acquire)
}
