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

use core::sync::atomic::Ordering;
use spin::Mutex;

#[derive(Default, Clone, Debug)]
pub struct MonsterStats {
    pub pci_devices: u64,
    pub nvme_bytes_rw: u64,
    pub usb_devices: u64,
    pub net_rx: u64,
    pub net_tx: u64,
    pub gpu_memory: u64,
    pub audio_streams: u64,
    pub errors: u64,
    pub ticks: u64,
}

impl MonsterStats {
    pub const fn new() -> Self {
        Self {
            pci_devices: 0,
            nvme_bytes_rw: 0,
            usb_devices: 0,
            net_rx: 0,
            net_tx: 0,
            gpu_memory: 0,
            audio_streams: 0,
            errors: 0,
            ticks: 0,
        }
    }

    pub fn record_error(&mut self) {
        self.errors += 1;
    }

    pub fn tick(&mut self) {
        self.ticks = self.ticks.wrapping_add(1);
    }
}

pub static STATS: Mutex<MonsterStats> = Mutex::new(MonsterStats::new());
pub fn refresh_stats() {
    let pci_count = {
        let devs = crate::drivers::pci::scan_and_collect();
        devs.len() as u64
    };

    let nvme_rw = if let Some(ctrl) = crate::drivers::nvme::get_controller() {
        let s = ctrl.get_stats();
        s.bytes_read + s.bytes_written
    } else {
        0
    };

    let usb_devs = crate::drivers::usb::get_manager()
        .map(|m| m.devices().len() as u64)
        .unwrap_or(0);

    let (net_rx, net_tx) = if let Some(dev) = crate::drivers::virtio_net::get_virtio_net_device() {
        let s = &dev.lock().stats;
        (
            s.rx_bytes.load(Ordering::Relaxed),
            s.tx_bytes.load(Ordering::Relaxed),
        )
    } else {
        (0, 0)
    };

    let gpu_mem = crate::drivers::gpu::with_driver(|g| g.get_stats().memory_allocated).unwrap_or(0);
    let audio_streams = crate::drivers::audio::get_controller()
        .map(|c| c.get_stats().active_streams)
        .unwrap_or(0);

    let mut g = STATS.lock();
    g.pci_devices = pci_count;
    g.nvme_bytes_rw = nvme_rw;
    g.usb_devices = usb_devs;
    g.net_rx = net_rx;
    g.net_tx = net_tx;
    g.gpu_memory = gpu_mem;
    g.audio_streams = audio_streams;
}

pub fn get_stats() -> MonsterStats {
    refresh_stats();
    STATS.lock().clone()
}

pub fn tick() {
    STATS.lock().tick();
}

pub fn record_error() {
    STATS.lock().record_error();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stats_default() {
        let stats = MonsterStats::new();
        assert_eq!(stats.pci_devices, 0);
        assert_eq!(stats.errors, 0);
        assert_eq!(stats.ticks, 0);
    }

    #[test]
    fn test_stats_tick() {
        let mut stats = MonsterStats::new();
        stats.tick();
        assert_eq!(stats.ticks, 1);
        stats.tick();
        assert_eq!(stats.ticks, 2);
    }

    #[test]
    fn test_stats_error() {
        let mut stats = MonsterStats::new();
        stats.record_error();
        assert_eq!(stats.errors, 1);
    }
}
