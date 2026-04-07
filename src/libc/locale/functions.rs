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

use core::ptr;
use super::lconv::{Lconv, C_LOCALE, EMPTY_STRING, LCONV};

#[no_mangle]
pub unsafe extern "C" fn setlocale(_category: i32, locale: *const u8) -> *const u8 {
    if locale.is_null() || ptr::read(locale) == 0 || (ptr::read(locale) == b'C' && ptr::read(locale.add(1)) == 0) {
        return C_LOCALE.as_ptr();
    }
    let len = crate::libc::string::strlen::strlen(locale);
    if len == 5 {
        let posix = b"POSIX";
        let mut matches = true;
        for i in 0..5 { if ptr::read(locale.add(i)) != posix[i] { matches = false; break; } }
        if matches { return C_LOCALE.as_ptr(); }
    }
    C_LOCALE.as_ptr()
}

#[no_mangle]
pub unsafe extern "C" fn localeconv() -> *mut Lconv { &raw mut LCONV }

#[no_mangle]
pub unsafe extern "C" fn nl_langinfo(_item: i32) -> *const u8 { EMPTY_STRING.as_ptr() }
