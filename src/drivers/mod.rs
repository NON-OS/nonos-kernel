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

pub mod ahci;
pub mod audio;
pub mod block;
#[cfg(target_arch = "x86_64")]
pub mod console;
mod critical;
mod device_info;
pub mod e1000;
mod exports;
pub mod gpu;
pub mod i2c;
mod init;
pub mod init_dma;
pub mod init_network;
pub mod init_peripherals;
pub mod init_storage;
#[cfg(target_arch = "x86_64")]
pub mod keyboard;
pub mod keyboard_buffer;
pub mod monster;
pub mod network;
pub mod nvme;
pub mod pci;
#[cfg(target_arch = "x86_64")]
pub mod rtl8139;
pub mod rtl8168;
pub mod security;
mod stats;
pub mod tpm;
pub mod usb;
#[cfg(target_arch = "x86_64")]
pub mod vga;
pub mod virtio_blk;
pub mod virtio_net;
pub mod virtio_rng;
pub mod wifi;
pub mod xhci;

pub use crate::arch::x86_64::pci::{DmaDescriptor, DmaEngine, MsixCapability, MsixTableEntry};
pub use audio::{
    get_controller as get_audio_controller, init_hd_audio, AudioError, AudioFormat, AudioStats,
    HdAudioController,
};
pub use block::{is_open, open_count};
pub use critical::{get_critical_drivers, CriticalDriver, DriverType, SecurityLevel};
pub use device_info::{get_all_devices, DeviceInfo, SecurityStatus};
pub use exports::*;
pub use gpu::{
    init_gpu, with_driver as with_gpu_driver, DisplayMode, GpuDriver, GpuStats, GpuSurface,
    PixelFormat,
};
pub use i2c::{
    controller_count as i2c_controller_count, get_controller as get_i2c_controller,
    init as init_i2c, read as i2c_read, write as i2c_write, write_read as i2c_write_read,
    DesignWareI2c, I2cAddress, I2cError, I2cSpeed, LpssController,
};
pub use init::init_all_drivers;
pub use init_dma::init_dma_subsystem;
pub use init_network::init_network_drivers;
pub use init_peripherals::init_peripheral_drivers;
pub use init_storage::init_storage_drivers;
pub use pci::{get_pci_manager, init_pci, PciBar, PciCapability, PciDevice, PciManager, PciStats};
pub use security::{
    is_config_write_allowed, safe_mmio_read32, safe_mmio_write32, validate_dma_buffer,
    validate_lba_range, validate_mmio_region, validate_pci_access, validate_prp_list, DriverError,
    DriverOpType, RateLimiter,
};
pub use stats::{get_hardware_stats, HardwareStats};
