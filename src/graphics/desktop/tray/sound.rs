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

use crate::drivers::audio;
use core::sync::atomic::{AtomicU8, Ordering};

const MAX_NAME_LEN: usize = 24;

#[derive(Clone, Copy)]
pub(super) struct AudioDevice {
    pub name: [u8; MAX_NAME_LEN],
    pub name_len: usize,
    pub is_output: bool,
}

impl AudioDevice {
    pub(super) const fn empty() -> Self {
        Self { name: [0u8; MAX_NAME_LEN], name_len: 0, is_output: true }
    }
}

static CURRENT_OUTPUT: AtomicU8 = AtomicU8::new(0);
static mut OUTPUT_DEVICES: [AudioDevice; 4] = [AudioDevice::empty(); 4];
static mut OUTPUT_COUNT: usize = 0;

pub(super) fn init_devices() {
    if audio::is_initialized() {
        unsafe {
            OUTPUT_DEVICES[0] = make_device(b"HD Audio Output");
            OUTPUT_COUNT = 1;
        }
    }
}

fn make_device(name: &[u8]) -> AudioDevice {
    let mut d = AudioDevice::empty();
    d.name_len = name.len().min(MAX_NAME_LEN);
    for i in 0..d.name_len {
        d.name[i] = name[i];
    }
    d.is_output = true;
    d
}

pub fn get_volume() -> u8 {
    audio::get_controller().map(|c| c.get_volume().percent()).unwrap_or(0)
}

pub fn set_volume(vol: u8) {
    if let Some(ctrl) = audio::get_controller() {
        let _ = ctrl.set_volume(vol.min(100));
    }
}

pub(super) fn is_muted() -> bool {
    audio::get_controller().map(|c| c.is_muted()).unwrap_or(false)
}

pub(super) fn toggle_mute() {
    if let Some(ctrl) = audio::get_controller() {
        let _ = ctrl.toggle_mute();
    }
}

pub fn get_output_device() -> u8 {
    CURRENT_OUTPUT.load(Ordering::Relaxed)
}

pub fn set_output_device(idx: u8) {
    unsafe {
        if (idx as usize) < OUTPUT_COUNT {
            CURRENT_OUTPUT.store(idx, Ordering::Relaxed);
        }
    }
}

pub(super) fn get_output_devices() -> impl Iterator<Item = &'static AudioDevice> {
    unsafe { OUTPUT_DEVICES[..OUTPUT_COUNT].iter() }
}

pub(super) fn handle_item_click(item: u8) {
    if item == 0 {
        toggle_mute();
    } else {
        set_output_device(item - 1);
    }
}
