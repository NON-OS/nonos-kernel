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

use core::sync::atomic::{AtomicU32, AtomicU8, AtomicUsize, Ordering};

pub(super) const VIEW_LIST: u8 = 0;
pub(super) const VIEW_CHAT: u8 = 1;
pub(super) const VIEW_CREATE: u8 = 2;
pub(super) const VIEW_DASHBOARD: u8 = 3;

static CURRENT_VIEW: AtomicU8 = AtomicU8::new(VIEW_DASHBOARD);
static SELECTED_AGENT: AtomicU32 = AtomicU32::new(0);
static INPUT_FOCUSED: AtomicU8 = AtomicU8::new(0);

pub(super) static mut INPUT_BUF: [u8; 512] = [0; 512];
pub(super) static INPUT_LEN: AtomicUsize = AtomicUsize::new(0);

pub(super) fn view() -> u8 {
    CURRENT_VIEW.load(Ordering::Relaxed)
}
pub(super) fn set_view(v: u8) {
    CURRENT_VIEW.store(v, Ordering::Relaxed);
}
pub(super) fn selected() -> u32 {
    SELECTED_AGENT.load(Ordering::Relaxed)
}
pub(super) fn set_selected(id: u32) {
    SELECTED_AGENT.store(id, Ordering::Relaxed);
}
pub(super) fn input_focused() -> bool {
    INPUT_FOCUSED.load(Ordering::Relaxed) == 1
}
pub(super) fn set_input_focused(v: bool) {
    INPUT_FOCUSED.store(if v { 1 } else { 0 }, Ordering::Relaxed);
}
pub(super) fn input_len() -> usize {
    INPUT_LEN.load(Ordering::Relaxed)
}
pub(super) fn set_input_len(v: usize) {
    INPUT_LEN.store(v, Ordering::Relaxed);
}
