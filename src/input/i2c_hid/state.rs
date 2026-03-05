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

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicI32, AtomicU32, Ordering};
use spin::Mutex;

use super::device::I2cHidDevice;


pub static DEVICES: Mutex<Vec<I2cHidDevice>> = Mutex::new(Vec::new());

pub static TOUCHPAD_AVAILABLE: AtomicBool = AtomicBool::new(false);

pub static CURSOR_X: AtomicI32 = AtomicI32::new(400);

pub static CURSOR_Y: AtomicI32 = AtomicI32::new(300);

pub static SCREEN_W: AtomicI32 = AtomicI32::new(800);

pub static SCREEN_H: AtomicI32 = AtomicI32::new(600);

pub static UPDATE_COUNT: AtomicU32 = AtomicU32::new(0);


#[inline]
pub fn is_available() -> bool {
    TOUCHPAD_AVAILABLE.load(Ordering::Acquire)
}

#[inline]
pub fn set_available(available: bool) {
    TOUCHPAD_AVAILABLE.store(available, Ordering::Release);
}

#[inline]
pub fn get_cursor() -> (i32, i32) {
    (
        CURSOR_X.load(Ordering::Acquire),
        CURSOR_Y.load(Ordering::Acquire),
    )
}

pub fn set_cursor(x: i32, y: i32) {
    let w = SCREEN_W.load(Ordering::Acquire);
    let h = SCREEN_H.load(Ordering::Acquire);

    let clamped_x = x.clamp(0, w.saturating_sub(1));
    let clamped_y = y.clamp(0, h.saturating_sub(1));

    CURSOR_X.store(clamped_x, Ordering::Release);
    CURSOR_Y.store(clamped_y, Ordering::Release);
}

pub fn move_cursor(dx: i32, dy: i32) {
    let x = CURSOR_X.load(Ordering::Acquire);
    let y = CURSOR_Y.load(Ordering::Acquire);
    set_cursor(x.saturating_add(dx), y.saturating_add(dy));
}

pub fn set_screen_size(width: u32, height: u32) {
    let w = width as i32;
    let h = height as i32;

    SCREEN_W.store(w, Ordering::Release);
    SCREEN_H.store(h, Ordering::Release);

    CURSOR_X.store(w / 2, Ordering::Release);
    CURSOR_Y.store(h / 2, Ordering::Release);
}

#[inline]
pub fn get_screen_size() -> (i32, i32) {
    (
        SCREEN_W.load(Ordering::Acquire),
        SCREEN_H.load(Ordering::Acquire),
    )
}

pub fn record_update() {
    let _ = UPDATE_COUNT.fetch_add(1, Ordering::Relaxed);
}

#[inline]
pub fn get_update_count() -> u32 {
    UPDATE_COUNT.load(Ordering::Relaxed)
}

pub fn device_count() -> usize {
    DEVICES.lock().len()
}

pub fn add_device(device: I2cHidDevice) {
    DEVICES.lock().push(device);
}
