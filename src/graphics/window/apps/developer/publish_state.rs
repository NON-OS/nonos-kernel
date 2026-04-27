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

pub(super) static FIELD_FOCUS: AtomicU8 = AtomicU8::new(0);
pub(super) static mut NAME_BUF: [u8; 32] = [0; 32];
pub(super) static NAME_LEN: AtomicU8 = AtomicU8::new(0);
pub(super) static mut PRICE_BUF: [u8; 8] = [0; 8];
pub(super) static PRICE_LEN: AtomicU8 = AtomicU8::new(0);

pub(super) fn focus() -> u8 {
    FIELD_FOCUS.load(Ordering::Relaxed)
}
pub(super) fn set_focus(v: u8) {
    FIELD_FOCUS.store(v, Ordering::Relaxed);
}
pub(super) fn name_len() -> u8 {
    NAME_LEN.load(Ordering::Relaxed)
}
pub(super) fn set_name_len(v: u8) {
    NAME_LEN.store(v, Ordering::Relaxed);
}
pub(super) fn price_len() -> u8 {
    PRICE_LEN.load(Ordering::Relaxed)
}
pub(super) fn set_price_len(v: u8) {
    PRICE_LEN.store(v, Ordering::Relaxed);
}
pub(super) fn name_buf() -> &'static [u8] {
    unsafe { &*core::ptr::addr_of!(NAME_BUF) }
}
pub(super) fn price_buf() -> &'static [u8] {
    unsafe { &*core::ptr::addr_of!(PRICE_BUF) }
}
