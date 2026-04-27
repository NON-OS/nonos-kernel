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

use core::sync::atomic::{AtomicU8, Ordering};

pub(super) const TAB_OVERVIEW: u8 = 0;
pub(super) const TAB_MY_APPS: u8 = 1;
pub(super) const TAB_PUBLISH: u8 = 2;
pub(super) const TAB_ANALYTICS: u8 = 3;
pub(super) const TAB_DOCS: u8 = 4;

static CURRENT_TAB: AtomicU8 = AtomicU8::new(0);

pub(super) fn current_tab() -> u8 {
    CURRENT_TAB.load(Ordering::Relaxed)
}
pub(super) fn set_tab(t: u8) {
    CURRENT_TAB.store(t, Ordering::Relaxed);
}
