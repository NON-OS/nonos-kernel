// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use core::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};

pub const MAX_MESSAGE_LEN: usize = 128;
pub const MAX_TITLE_LEN: usize = 32;
pub const MAX_INPUT_LEN: usize = 64;

pub static DIALOG_ACTIVE: AtomicBool = AtomicBool::new(false);
pub static DIALOG_TYPE: AtomicU8 = AtomicU8::new(0);
pub static DIALOG_RESULT: AtomicU8 = AtomicU8::new(0);
pub static mut DIALOG_MESSAGE: [u8; MAX_MESSAGE_LEN] = [0u8; MAX_MESSAGE_LEN];
pub static mut DIALOG_MESSAGE_LEN: usize = 0;
pub static mut DIALOG_TITLE: [u8; MAX_TITLE_LEN] = [0u8; MAX_TITLE_LEN];
pub static mut DIALOG_TITLE_LEN: usize = 0;

pub static mut DIALOG_INPUT_BUF: [u8; MAX_INPUT_LEN] = [0u8; MAX_INPUT_LEN];
pub static DIALOG_INPUT_LEN: AtomicUsize = AtomicUsize::new(0);
pub static DIALOG_INPUT_CALLBACK: AtomicU8 = AtomicU8::new(0);

pub const INPUT_CB_NONE: u8 = 0;
pub const INPUT_CB_DESKTOP_NEW_FOLDER: u8 = 1;
pub const INPUT_CB_DESKTOP_NEW_FILE: u8 = 2;
pub const INPUT_CB_FM_NEW_FOLDER: u8 = 3;
pub const INPUT_CB_FM_RENAME: u8 = 4;

pub const DIALOG_INFO: u8 = 0;
pub const DIALOG_WARNING: u8 = 1;
pub const DIALOG_ERROR: u8 = 2;
pub const DIALOG_CONFIRM: u8 = 3;
pub const DIALOG_INPUT: u8 = 4;

pub const RESULT_NONE: u8 = 0;
pub const RESULT_OK: u8 = 1;
pub const RESULT_CANCEL: u8 = 2;
pub const RESULT_YES: u8 = 3;
pub const RESULT_NO: u8 = 4;

pub fn show_dialog(dtype: u8, title: &[u8], message: &[u8]) {
    let title_len = title.len().min(MAX_TITLE_LEN);
    let msg_len = message.len().min(MAX_MESSAGE_LEN);
    unsafe {
        for i in 0..title_len {
            DIALOG_TITLE[i] = title[i];
        }
        DIALOG_TITLE_LEN = title_len;
        for i in 0..msg_len {
            DIALOG_MESSAGE[i] = message[i];
        }
        DIALOG_MESSAGE_LEN = msg_len;
    }
    DIALOG_TYPE.store(dtype, Ordering::Relaxed);
    DIALOG_RESULT.store(RESULT_NONE, Ordering::Relaxed);
    DIALOG_ACTIVE.store(true, Ordering::Relaxed);
}

pub fn is_active() -> bool {
    DIALOG_ACTIVE.load(Ordering::Relaxed)
}
pub fn get_result() -> u8 {
    DIALOG_RESULT.load(Ordering::Relaxed)
}
pub fn close() {
    DIALOG_ACTIVE.store(false, Ordering::Relaxed);
    DIALOG_RESULT.store(RESULT_NONE, Ordering::Relaxed);
    DIALOG_INPUT_LEN.store(0, Ordering::Relaxed);
    DIALOG_INPUT_CALLBACK.store(INPUT_CB_NONE, Ordering::Relaxed);
}

pub fn show_input(title: &[u8], message: &[u8], callback_id: u8) {
    let title_len = title.len().min(MAX_TITLE_LEN);
    let msg_len = message.len().min(MAX_MESSAGE_LEN);
    unsafe {
        for i in 0..title_len {
            DIALOG_TITLE[i] = title[i];
        }
        DIALOG_TITLE_LEN = title_len;
        for i in 0..msg_len {
            DIALOG_MESSAGE[i] = message[i];
        }
        DIALOG_MESSAGE_LEN = msg_len;
        let ptr = core::ptr::addr_of_mut!(DIALOG_INPUT_BUF);
        (*ptr).fill(0);
    }
    DIALOG_INPUT_LEN.store(0, Ordering::Relaxed);
    DIALOG_INPUT_CALLBACK.store(callback_id, Ordering::Relaxed);
    DIALOG_TYPE.store(DIALOG_INPUT, Ordering::Relaxed);
    DIALOG_RESULT.store(RESULT_NONE, Ordering::Relaxed);
    DIALOG_ACTIVE.store(true, Ordering::Relaxed);
}

pub fn input_push_char(ch: u8) {
    let len = DIALOG_INPUT_LEN.load(Ordering::Relaxed);
    if len < MAX_INPUT_LEN - 1 {
        unsafe {
            DIALOG_INPUT_BUF[len] = ch;
        }
        DIALOG_INPUT_LEN.store(len + 1, Ordering::Relaxed);
    }
}

pub fn input_pop_char() {
    let len = DIALOG_INPUT_LEN.load(Ordering::Relaxed);
    if len > 0 {
        unsafe {
            DIALOG_INPUT_BUF[len - 1] = 0;
        }
        DIALOG_INPUT_LEN.store(len - 1, Ordering::Relaxed);
    }
}

pub fn get_input_text() -> &'static str {
    let len = DIALOG_INPUT_LEN.load(Ordering::Relaxed);
    unsafe { core::str::from_utf8_unchecked(&DIALOG_INPUT_BUF[..len]) }
}

pub fn get_input_callback() -> u8 {
    DIALOG_INPUT_CALLBACK.load(Ordering::Relaxed)
}

pub fn is_input_dialog() -> bool {
    DIALOG_ACTIVE.load(Ordering::Relaxed) && DIALOG_TYPE.load(Ordering::Relaxed) == DIALOG_INPUT
}
