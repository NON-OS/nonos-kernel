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

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

pub static GOTO_ACTIVE: AtomicBool = AtomicBool::new(false);
pub static GOTO_LINE_NUM: AtomicUsize = AtomicUsize::new(0);
pub static GOTO_INPUT: [AtomicU8; 10] = {
    const INIT: AtomicU8 = AtomicU8::new(0);
    [INIT; 10]
};
pub static GOTO_INPUT_LEN: AtomicUsize = AtomicUsize::new(0);

pub fn open_goto() {
    GOTO_ACTIVE.store(true, Ordering::Release);
    GOTO_INPUT_LEN.store(0, Ordering::Release);
}

pub fn close_goto() {
    GOTO_ACTIVE.store(false, Ordering::Release);
}

pub fn is_active() -> bool {
    GOTO_ACTIVE.load(Ordering::Acquire)
}

pub fn goto_input_key(ch: u8) {
    if !ch.is_ascii_digit() {
        return;
    }
    let len = GOTO_INPUT_LEN.load(Ordering::Acquire);
    if len >= 10 {
        return;
    }
    GOTO_INPUT[len].store(ch, Ordering::Release);
    GOTO_INPUT_LEN.store(len + 1, Ordering::Release);
}

pub fn goto_confirm() -> bool {
    let len = GOTO_INPUT_LEN.load(Ordering::Acquire);
    if len == 0 {
        close_goto();
        return false;
    }
    let mut num = 0usize;
    for i in 0..len.min(10) {
        let ch = GOTO_INPUT[i].load(Ordering::Acquire);
        num = num.saturating_mul(10).saturating_add((ch.wrapping_sub(b'0')) as usize);
    }
    if num > 0 {
        num -= 1;
    }
    super::cursor::goto_line(num);
    close_goto();
    true
}

pub fn get_input() -> [u8; 10] {
    let mut buf = [0u8; 10];
    let len = GOTO_INPUT_LEN.load(Ordering::Acquire).min(10);
    for i in 0..len {
        buf[i] = GOTO_INPUT[i].load(Ordering::Acquire);
    }
    buf
}
