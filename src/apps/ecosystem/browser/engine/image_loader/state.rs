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

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

pub(super) static IMAGE_LOAD_COUNT: AtomicU32 = AtomicU32::new(0);
pub(super) static FETCH_DISABLED: AtomicBool = AtomicBool::new(false);

pub fn reset_image_count() {
    IMAGE_LOAD_COUNT.store(0, Ordering::Relaxed);
}

pub fn disable_fetch() {
    FETCH_DISABLED.store(true, Ordering::Release);
}

pub fn enable_fetch() {
    FETCH_DISABLED.store(false, Ordering::Release);
}
