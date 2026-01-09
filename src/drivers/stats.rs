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

use super::{
    get_ahci_controller, get_audio_controller, get_pci_manager, get_xhci_controller,
    with_gpu_driver, AhciStats, AudioStats, GpuStats, PciStats, XhciStats,
};

pub fn get_hardware_stats() -> HardwareStats {
    HardwareStats {
        pci_stats: get_pci_manager().map(|mgr| mgr.lock().get_stats()).unwrap_or_default(),
        nvme_stats: super::nvme::get_controller().map(|ctrl| ctrl.get_stats()).unwrap_or_default(),
        ahci_stats: get_ahci_controller().map(|ctrl| ctrl.get_stats()).unwrap_or_default(),
        xhci_stats: get_xhci_controller().map(|ctrl| ctrl.get_stats()).unwrap_or_default(),
        audio_stats: get_audio_controller().map(|ctrl| ctrl.get_stats()).unwrap_or_default(),
        gpu_stats: with_gpu_driver(|drv| drv.get_stats()).unwrap_or_default(),
    }
}

pub struct HardwareStats {
    pub pci_stats: PciStats,
    pub nvme_stats: super::nvme::NvmeStatsSnapshot,
    pub ahci_stats: AhciStats,
    pub xhci_stats: XhciStats,
    pub audio_stats: AudioStats,
    pub gpu_stats: GpuStats,
}

impl Default for HardwareStats {
    fn default() -> Self {
        Self {
            pci_stats: PciStats::default(),
            nvme_stats: super::nvme::NvmeStatsSnapshot::default(),
            ahci_stats: AhciStats {
                read_ops: 0,
                write_ops: 0,
                trim_ops: 0,
                errors: 0,
                bytes_read: 0,
                bytes_written: 0,
                devices_count: 0,
                port_resets: 0,
                validation_failures: 0,
            },
            xhci_stats: XhciStats::default(),
            audio_stats: AudioStats {
                samples_played: 0,
                samples_recorded: 0,
                buffer_underruns: 0,
                buffer_overruns: 0,
                interrupts_handled: 0,
                active_streams: 0,
                codecs_detected: 0,
                bytes_transferred: 0,
                error_count: 0,
            },
            gpu_stats: GpuStats {
                frames_rendered: 0,
                commands_executed: 0,
                memory_allocated: 0,
                gpu_errors: 0,
                surfaces_created: 0,
                shaders_loaded: 0,
                vendor_id: 0,
                device_id: 0,
            },
        }
    }
}
