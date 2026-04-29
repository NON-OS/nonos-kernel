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

const MAX_DEVICES: usize = 6;
const MAX_NAME_LEN: usize = 20;

#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum DeviceType {
    Headphones = 0,
    Keyboard = 1,
    Mouse = 2,
    Phone = 3,
    Other = 4,
}

#[derive(Clone, Copy)]
pub struct BluetoothDevice {
    pub name: [u8; MAX_NAME_LEN],
    pub name_len: usize,
    pub device_type: DeviceType,
    pub paired: bool,
    pub connected: bool,
}

impl BluetoothDevice {
    pub const fn empty() -> Self {
        Self {
            name: [0u8; MAX_NAME_LEN],
            name_len: 0,
            device_type: DeviceType::Other,
            paired: false,
            connected: false,
        }
    }
}

static mut DEVICES: [BluetoothDevice; MAX_DEVICES] = [BluetoothDevice::empty(); MAX_DEVICES];
static DEVICE_COUNT: AtomicU8 = AtomicU8::new(0);
static BT_ENABLED: AtomicBool = AtomicBool::new(true);

pub fn init_devices() {
    unsafe {
        DEVICES[0] = make_device(b"AirPods Pro", DeviceType::Headphones, true, true);
        DEVICES[1] = make_device(b"Magic Keyboard", DeviceType::Keyboard, true, false);
        DEVICES[2] = make_device(b"MX Master 3", DeviceType::Mouse, true, true);
    }
    DEVICE_COUNT.store(3, Ordering::Relaxed);
}

fn make_device(name: &[u8], dtype: DeviceType, paired: bool, connected: bool) -> BluetoothDevice {
    let mut d = BluetoothDevice::empty();
    d.name_len = name.len().min(MAX_NAME_LEN);
    for i in 0..d.name_len {
        d.name[i] = name[i];
    }
    d.device_type = dtype;
    d.paired = paired;
    d.connected = connected;
    d
}

pub fn get_bluetooth_devices() -> impl Iterator<Item = &'static BluetoothDevice> {
    let count = DEVICE_COUNT.load(Ordering::Relaxed) as usize;
    unsafe { DEVICES[..count].iter() }
}

pub fn pair_device(_idx: usize) {}
pub fn unpair_device(_idx: usize) {}

pub fn is_enabled() -> bool {
    BT_ENABLED.load(Ordering::Relaxed)
}

pub fn toggle_enabled() {
    let prev = BT_ENABLED.load(Ordering::Relaxed);
    BT_ENABLED.store(!prev, Ordering::Relaxed);
}

pub fn handle_item_click(item: u8) {
    if item == 0 {
        toggle_enabled();
    }
}
