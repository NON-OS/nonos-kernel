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

use core::sync::atomic::{AtomicUsize, AtomicBool, Ordering};
use crate::graphics::framebuffer::COLOR_TEXT_WHITE;
use super::constants::*;

pub(super) static mut TERM_BUFFER: [u8; TERM_BUFFER_SIZE] = [b' '; TERM_BUFFER_SIZE];
pub(super) static mut TERM_COLORS: [u32; TERM_BUFFER_SIZE] = [COLOR_TEXT_WHITE; TERM_BUFFER_SIZE];
pub(super) static TERM_CURSOR_X: AtomicUsize = AtomicUsize::new(0);
pub(super) static TERM_CURSOR_Y: AtomicUsize = AtomicUsize::new(0);
pub(super) static TERM_CURSOR_VISIBLE: AtomicBool = AtomicBool::new(true);

pub(super) static mut INPUT_BUFFER: [u8; MAX_INPUT_LEN] = [0u8; MAX_INPUT_LEN];
pub(super) static INPUT_LEN: AtomicUsize = AtomicUsize::new(0);
pub(super) static INPUT_CURSOR: AtomicUsize = AtomicUsize::new(0);

pub(super) static mut HISTORY: [[u8; HISTORY_ENTRY_LEN]; MAX_HISTORY] = [[0u8; HISTORY_ENTRY_LEN]; MAX_HISTORY];
pub(super) static mut HISTORY_LENS: [usize; MAX_HISTORY] = [0; MAX_HISTORY];
pub(super) static HISTORY_COUNT: AtomicUsize = AtomicUsize::new(0);
pub(super) static HISTORY_POS: AtomicUsize = AtomicUsize::new(0);

pub(super) static mut CWD: [u8; 128] = [0u8; 128];
pub(super) static CWD_LEN: AtomicUsize = AtomicUsize::new(0);

pub(super) fn add_to_history(cmd: &[u8]) {
    let count = HISTORY_COUNT.load(Ordering::Relaxed);
    let idx = count % MAX_HISTORY;
    let len = cmd.len().min(HISTORY_ENTRY_LEN);

    // SAFETY: Bounds checked above
    unsafe {
        HISTORY[idx][..len].copy_from_slice(&cmd[..len]);
        HISTORY_LENS[idx] = len;
    }

    HISTORY_COUNT.store(count + 1, Ordering::Relaxed);
    HISTORY_POS.store(count + 1, Ordering::Relaxed);
}
