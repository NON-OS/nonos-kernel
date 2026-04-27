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

use crate::fs::ramfs;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, Ordering};

pub(super) const MAX_ICONS: usize = 24;
pub(super) const NAME_LEN: usize = 16;
pub(super) const MAX_PATH: usize = 128;

pub(super) static ICON_COUNT: AtomicU8 = AtomicU8::new(0);
pub(super) static mut ICONS: [DesktopIcon; MAX_ICONS] = [DesktopIcon::empty(); MAX_ICONS];
pub(super) static mut CURRENT_PATH: [u8; MAX_PATH] = [0; MAX_PATH];
pub(super) static CURRENT_PATH_LEN: AtomicU8 = AtomicU8::new(4);
pub(super) static mut ICON_POSITIONS: [(i32, i32); MAX_ICONS] = [(-1, -1); MAX_ICONS];
pub(super) static DRAGGING_ICON: AtomicU8 = AtomicU8::new(255);
pub(super) static DRAG_OFFSET_X: AtomicI32 = AtomicI32::new(0);
pub(super) static DRAG_OFFSET_Y: AtomicI32 = AtomicI32::new(0);
pub(super) static IS_DRAGGING: AtomicBool = AtomicBool::new(false);
pub(super) static SELECTED_ICON: AtomicU8 = AtomicU8::new(255);

#[derive(Clone, Copy)]
pub(super) struct DesktopIcon {
    pub name: [u8; NAME_LEN],
    pub name_len: u8,
    pub is_dir: bool,
}

impl DesktopIcon {
    pub(super) const fn empty() -> Self {
        Self { name: [0; NAME_LEN], name_len: 0, is_dir: false }
    }
}

pub(super) fn init_path() {
    unsafe {
        if CURRENT_PATH[0] == 0 {
            CURRENT_PATH[..4].copy_from_slice(b"/ram");
            CURRENT_PATH_LEN.store(4, Ordering::SeqCst);
        }
    }
}

pub(crate) fn get_current_path() -> &'static str {
    init_path();
    let len = CURRENT_PATH_LEN.load(Ordering::SeqCst) as usize;
    unsafe { core::str::from_utf8_unchecked(&CURRENT_PATH[..len]) }
}

pub(crate) fn is_in_subfolder() -> bool {
    CURRENT_PATH_LEN.load(Ordering::SeqCst) > 4
}

pub(crate) fn refresh() {
    init_path();
    let path = get_current_path();
    let mut count = 0usize;
    if let Ok(entries) = ramfs::list_dir_entries(path) {
        for e in entries.iter().take(MAX_ICONS) {
            if e.name.starts_with('.') {
                continue;
            }
            unsafe {
                let len = e.name.len().min(NAME_LEN - 1);
                ICONS[count].name[..len].copy_from_slice(e.name.as_bytes());
                ICONS[count].name_len = len as u8;
                ICONS[count].is_dir = e.is_dir;
            }
            count += 1;
        }
    }
    ICON_COUNT.store(count as u8, Ordering::SeqCst);
}
