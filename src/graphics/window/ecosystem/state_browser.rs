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

extern crate alloc;

use alloc::string::String;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use spin::Mutex;

pub const MAX_URL_LEN: usize = 2048;

pub static URL_BUFFER: Mutex<[u8; MAX_URL_LEN]> = Mutex::new([0u8; MAX_URL_LEN]);
pub static URL_LEN: AtomicUsize = AtomicUsize::new(0);
pub static URL_CURSOR: AtomicUsize = AtomicUsize::new(0);
pub static URL_FOCUSED: AtomicBool = AtomicBool::new(true);
pub static LOADING: AtomicBool = AtomicBool::new(false);
pub static IS_HTTPS: AtomicBool = AtomicBool::new(false);
pub static CERT_VERIFIED: AtomicBool = AtomicBool::new(false);
pub static ERROR_MSG: Mutex<[u8; 128]> = Mutex::new([0u8; 128]);
pub static ERROR_LEN: AtomicUsize = AtomicUsize::new(0);

pub fn get_url_string() -> Option<String> {
    let buf = URL_BUFFER.lock();
    let len = URL_LEN.load(Ordering::Relaxed);
    if len > 0 {
        core::str::from_utf8(&buf[..len]).ok().map(String::from)
    } else {
        None
    }
}

pub fn set_url(url: &str) {
    let mut buf = URL_BUFFER.lock();
    let len = url.len().min(MAX_URL_LEN - 1);
    buf[..len].copy_from_slice(&url.as_bytes()[..len]);
    URL_LEN.store(len, Ordering::Relaxed);
    URL_CURSOR.store(len, Ordering::Relaxed);
}

pub fn clear_url() {
    URL_LEN.store(0, Ordering::Relaxed);
    URL_CURSOR.store(0, Ordering::Relaxed);
}

pub fn set_error(msg: &str) {
    let mut buf = ERROR_MSG.lock();
    let len = msg.len().min(127);
    buf[..len].copy_from_slice(&msg.as_bytes()[..len]);
    ERROR_LEN.store(len, Ordering::Relaxed);
}

pub fn clear_error() {
    ERROR_LEN.store(0, Ordering::Relaxed);
}

pub fn get_error() -> Option<String> {
    let len = ERROR_LEN.load(Ordering::Relaxed);
    if len > 0 {
        let buf = ERROR_MSG.lock();
        core::str::from_utf8(&buf[..len]).ok().map(String::from)
    } else {
        None
    }
}
