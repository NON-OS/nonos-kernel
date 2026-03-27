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

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

pub static GOTO_ACTIVE: AtomicBool = AtomicBool::new(false);
pub static GOTO_LINE_NUM: AtomicUsize = AtomicUsize::new(0);
pub static GOTO_INPUT: [u8; 10] = [0; 10];
pub static GOTO_INPUT_LEN: AtomicUsize = AtomicUsize::new(0);

pub fn open_goto() { GOTO_ACTIVE.store(true, Ordering::Relaxed); GOTO_INPUT_LEN.store(0, Ordering::Relaxed); }

pub fn close_goto() { GOTO_ACTIVE.store(false, Ordering::Relaxed); }

pub fn is_active() -> bool { GOTO_ACTIVE.load(Ordering::Relaxed) }

pub fn goto_input_key(ch: u8) {
    if !ch.is_ascii_digit() { return; }
    let len = GOTO_INPUT_LEN.load(Ordering::Relaxed);
    if len >= 10 { return; }
    unsafe { *(&GOTO_INPUT as *const _ as *mut [u8; 10]).as_mut().unwrap().get_unchecked_mut(len) = ch; }
    GOTO_INPUT_LEN.store(len + 1, Ordering::Relaxed);
}

pub fn goto_confirm() -> bool {
    let len = GOTO_INPUT_LEN.load(Ordering::Relaxed);
    if len == 0 { close_goto(); return false; }
    let mut num = 0usize;
    for i in 0..len {
        let ch = unsafe { *GOTO_INPUT.get_unchecked(i) };
        num = num * 10 + (ch - b'0') as usize;
    }
    if num > 0 { num -= 1; }
    super::cursor::goto_line(num);
    close_goto();
    true
}

pub fn get_input() -> &'static [u8] {
    let len = GOTO_INPUT_LEN.load(Ordering::Relaxed);
    unsafe { &*core::ptr::slice_from_raw_parts(GOTO_INPUT.as_ptr(), len) }
}
