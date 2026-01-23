// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

mod azerty;
mod colemak;
mod dvorak;
mod qwertz;
mod spanish;
pub mod types;
mod uk_qwerty;
mod us_qwerty;

pub use types::{DeadKey, Layout, LayoutInfo};

use core::sync::atomic::{AtomicU8, Ordering};
use spin::RwLock;

static CURRENT_LAYOUT: AtomicU8 = AtomicU8::new(Layout::UsQwerty as u8);
static PENDING_DEAD_KEY: RwLock<Option<DeadKey>> = RwLock::new(None);

pub fn get_layout() -> Layout {
    Layout::from_u8(CURRENT_LAYOUT.load(Ordering::Acquire)).unwrap_or(Layout::UsQwerty)
}

pub fn set_layout(layout: Layout) {
    CURRENT_LAYOUT.store(layout as u8, Ordering::Release);
    clear_pending_dead_key();
}

pub fn get_layout_info() -> &'static LayoutInfo {
    get_layout_info_for(get_layout())
}

pub fn get_layout_info_for(layout: Layout) -> &'static LayoutInfo {
    match layout {
        Layout::UsQwerty => &us_qwerty::LAYOUT_INFO,
        Layout::Dvorak => &dvorak::LAYOUT_INFO,
        Layout::Azerty => &azerty::LAYOUT_INFO,
        Layout::Colemak => &colemak::LAYOUT_INFO,
        Layout::Qwertz => &qwertz::LAYOUT_INFO,
        Layout::UkQwerty => &uk_qwerty::LAYOUT_INFO,
        Layout::Spanish => &spanish::LAYOUT_INFO,
        Layout::Custom => &us_qwerty::LAYOUT_INFO,
    }
}

pub fn set_pending_dead_key(dk: DeadKey) {
    *PENDING_DEAD_KEY.write() = Some(dk);
}

pub fn clear_pending_dead_key() {
    *PENDING_DEAD_KEY.write() = None;
}

pub fn take_pending_dead_key() -> Option<DeadKey> {
    PENDING_DEAD_KEY.write().take()
}

pub fn has_pending_dead_key() -> bool {
    PENDING_DEAD_KEY.read().is_some()
}

pub fn process_with_dead_key(ch: u8) -> u8 {
    if let Some(dk) = take_pending_dead_key() {
        dk.compose(ch).unwrap_or(ch)
    } else {
        ch
    }
}

pub fn get_ascii_mapping(layout: Layout) -> &'static [u8; 128] {
    get_layout_info_for(layout).base
}

pub fn get_shifted_mapping(layout: Layout) -> &'static [u8; 128] {
    get_layout_info_for(layout).shift
}

pub fn get_altgr_mapping(layout: Layout) -> &'static [u8; 128] {
    get_layout_info_for(layout).altgr
}
