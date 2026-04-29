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

use super::history::add_to_history;
use core::sync::atomic::{AtomicU8, AtomicUsize, Ordering};

const MAX_CLIPBOARD_SIZE: usize = 65536;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ContentType {
    Empty = 0,
    Text = 1,
    Binary = 2,
    FilePath = 3,
}

static CONTENT_TYPE: AtomicU8 = AtomicU8::new(0);
static CONTENT_LEN: AtomicUsize = AtomicUsize::new(0);
static mut CLIPBOARD_DATA: [u8; MAX_CLIPBOARD_SIZE] = [0u8; MAX_CLIPBOARD_SIZE];

pub fn has_content() -> bool {
    CONTENT_TYPE.load(Ordering::Relaxed) != 0
}

pub(super) fn get_content_type() -> ContentType {
    match CONTENT_TYPE.load(Ordering::Relaxed) {
        1 => ContentType::Text,
        2 => ContentType::Binary,
        3 => ContentType::FilePath,
        _ => ContentType::Empty,
    }
}

pub fn copy_text(text: &[u8]) {
    let len = text.len().min(MAX_CLIPBOARD_SIZE);
    unsafe {
        for i in 0..len {
            CLIPBOARD_DATA[i] = text[i];
        }
    }
    CONTENT_LEN.store(len, Ordering::Relaxed);
    CONTENT_TYPE.store(ContentType::Text as u8, Ordering::Relaxed);
    add_to_history(text, ContentType::Text);
}

pub fn copy_binary(data: &[u8]) {
    let len = data.len().min(MAX_CLIPBOARD_SIZE);
    unsafe {
        for i in 0..len {
            CLIPBOARD_DATA[i] = data[i];
        }
    }
    CONTENT_LEN.store(len, Ordering::Relaxed);
    CONTENT_TYPE.store(ContentType::Binary as u8, Ordering::Relaxed);
    add_to_history(data, ContentType::Binary);
}

pub fn get_text() -> Option<&'static [u8]> {
    if get_content_type() != ContentType::Text {
        return None;
    }
    let len = CONTENT_LEN.load(Ordering::Relaxed);
    unsafe { Some(&CLIPBOARD_DATA[..len]) }
}

pub fn get_binary() -> Option<&'static [u8]> {
    if get_content_type() != ContentType::Binary {
        return None;
    }
    let len = CONTENT_LEN.load(Ordering::Relaxed);
    unsafe { Some(&CLIPBOARD_DATA[..len]) }
}

pub fn clear() {
    CONTENT_TYPE.store(0, Ordering::Relaxed);
    CONTENT_LEN.store(0, Ordering::Relaxed);
}
