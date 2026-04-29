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

use crate::sys::settings::api;
use core::sync::atomic::{AtomicBool, Ordering};

static DO_NOT_DISTURB: AtomicBool = AtomicBool::new(false);
static AIRPLANE_MODE: AtomicBool = AtomicBool::new(false);
static NIGHT_SHIFT: AtomicBool = AtomicBool::new(false);
static AIRPLAY: AtomicBool = AtomicBool::new(false);

pub fn get_brightness() -> u8 {
    api::brightness()
}

pub fn set_brightness(val: u8) {
    api::set_brightness(val.min(100));
}

pub fn get_do_not_disturb() -> bool {
    DO_NOT_DISTURB.load(Ordering::Relaxed)
}

pub fn toggle_do_not_disturb() {
    let prev = DO_NOT_DISTURB.load(Ordering::Relaxed);
    DO_NOT_DISTURB.store(!prev, Ordering::Relaxed);
}

pub(super) fn get_airplane_mode() -> bool {
    AIRPLANE_MODE.load(Ordering::Relaxed)
}

pub(super) fn toggle_airplane_mode() {
    let prev = AIRPLANE_MODE.load(Ordering::Relaxed);
    AIRPLANE_MODE.store(!prev, Ordering::Relaxed);
    if !prev {
        super::wifi::toggle_enabled();
        super::bluetooth::toggle_enabled();
    }
}

pub(super) fn get_night_shift() -> bool {
    NIGHT_SHIFT.load(Ordering::Relaxed)
}

pub(super) fn toggle_night_shift() {
    let prev = NIGHT_SHIFT.load(Ordering::Relaxed);
    NIGHT_SHIFT.store(!prev, Ordering::Relaxed);
}

pub(super) fn get_airplay() -> bool {
    AIRPLAY.load(Ordering::Relaxed)
}

pub(super) fn toggle_airplay() {
    let prev = AIRPLAY.load(Ordering::Relaxed);
    AIRPLAY.store(!prev, Ordering::Relaxed);
}

pub(super) fn handle_item_click(item: u8) {
    match item {
        0 => super::wifi::toggle_enabled(),
        1 => super::bluetooth::toggle_enabled(),
        2 => toggle_airplane_mode(),
        3 => toggle_do_not_disturb(),
        4 => toggle_night_shift(),
        5 => toggle_airplay(),
        _ => {}
    }
}
