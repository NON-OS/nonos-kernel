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

mod pci;
mod platform;
mod system;

pub use pci::*;
pub use platform::*;
pub use system::*;

use super::kobject::{register_kobject, KobjectType};

static mut DEVICES_INO: u64 = 200;

pub fn init_devices_subsystem() {
    unsafe {
        DEVICES_INO = 200;
    }
    pci::init_pci_devices();
    platform::init_platform_devices();
    system::init_system_devices();
}

pub fn get_devices_ino() -> u64 {
    unsafe { DEVICES_INO }
}

pub fn register_device(name: &str, parent: u64) -> u64 {
    register_kobject(name, KobjectType::Device, parent)
}

pub fn register_root_device(name: &str) -> u64 {
    register_kobject(name, KobjectType::Device, get_devices_ino())
}
