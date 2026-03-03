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
use spin::Mutex;

use super::super::backend::UsbHostBackend;
use super::super::device::UsbDevice;
use super::super::class_driver::bind_drivers_to_device;
use super::stats::{UsbStats, UsbStatsSnapshot};

pub struct UsbManager<B: UsbHostBackend> {
    pub(super) backend: B,
    pub(super) devices: Mutex<Vec<UsbDevice>>,
    pub(super) stats: UsbStats,
}

impl<B: UsbHostBackend> UsbManager<B> {
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            devices: Mutex::new(Vec::new()),
            stats: UsbStats::default(),
        }
    }

    pub fn bind_class_drivers(&self) {
        let devs = self.devices.lock().clone();
        for dev in &devs {
            bind_drivers_to_device(dev);
        }
    }

    pub fn devices(&self) -> Vec<UsbDevice> {
        self.devices.lock().clone()
    }

    pub fn device_count(&self) -> usize {
        self.devices.lock().len()
    }

    pub fn stats(&self) -> UsbStatsSnapshot {
        self.stats.snapshot()
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }
}
