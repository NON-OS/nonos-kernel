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

use core::sync::atomic::{AtomicBool, AtomicU8, Ordering};

static OUTPUT_VOLUME: AtomicU8 = AtomicU8::new(80);
static INPUT_VOLUME: AtomicU8 = AtomicU8::new(50);
static ALERT_VOLUME: AtomicU8 = AtomicU8::new(100);
static OUTPUT_DEVICE: AtomicU8 = AtomicU8::new(0);
static INPUT_DEVICE: AtomicU8 = AtomicU8::new(0);
static OUTPUT_MUTED: AtomicBool = AtomicBool::new(false);
static INPUT_MUTED: AtomicBool = AtomicBool::new(false);
static BALANCE: AtomicU8 = AtomicU8::new(50);

#[derive(Clone, Copy)]
pub struct SoundState {
    pub output_volume: u8,
    pub input_volume: u8,
    pub alert_volume: u8,
    pub output_device_id: u8,
    pub input_device_id: u8,
    pub output_muted: bool,
    pub input_muted: bool,
    pub balance: u8,
}

pub(super) fn get_state() -> SoundState {
    SoundState {
        output_volume: OUTPUT_VOLUME.load(Ordering::Relaxed),
        input_volume: INPUT_VOLUME.load(Ordering::Relaxed),
        alert_volume: ALERT_VOLUME.load(Ordering::Relaxed),
        output_device_id: OUTPUT_DEVICE.load(Ordering::Relaxed),
        input_device_id: INPUT_DEVICE.load(Ordering::Relaxed),
        output_muted: OUTPUT_MUTED.load(Ordering::Relaxed),
        input_muted: INPUT_MUTED.load(Ordering::Relaxed),
        balance: BALANCE.load(Ordering::Relaxed),
    }
}

pub(super) fn set_output_volume(vol: u8) {
    let v = vol.min(100);
    OUTPUT_VOLUME.store(v, Ordering::Relaxed);
    if let Some(ctrl) = crate::drivers::audio::get_controller() {
        let _ = ctrl.set_volume(v);
    }
}

pub(super) fn set_input_volume(vol: u8) {
    INPUT_VOLUME.store(vol.min(100), Ordering::Relaxed);
}

pub(super) fn set_output_device(id: u8) {
    OUTPUT_DEVICE.store(id, Ordering::Relaxed);
}

pub(super) fn set_output_muted(muted: bool) {
    OUTPUT_MUTED.store(muted, Ordering::Relaxed);
    if let Some(ctrl) = crate::drivers::audio::get_controller() {
        let _ = ctrl.set_mute(muted);
    }
}

pub(super) fn set_balance(b: u8) {
    BALANCE.store(b.min(100), Ordering::Relaxed);
}
