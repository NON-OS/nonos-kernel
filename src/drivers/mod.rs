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

// Microkernel hardware bring-up surface. The boot path needs PCI
// enumeration (from `init_core_systems`), the virtio-rng entropy probe
// (from `init_entropy`), and the security helpers used by the trusted
// memory/IPC paths.
//
// `device_info` enumerates devices through the legacy `critical`
// taxonomy and only ships diagnostics for the gated audio/gpu/xhci/ahci
// stack; no microkernel caller reads it.
#[cfg(feature = "nonos-legacy-tree")]
mod device_info;
pub mod pci;
pub mod security;
pub mod virtio_rng;

#[cfg(feature = "nonos-legacy-tree")]
pub use device_info::{get_all_devices, DeviceInfo, SecurityStatus};
pub use pci::{get_pci_manager, init_pci, PciBar, PciCapability, PciDevice, PciManager, PciStats};
pub use security::{
    is_config_write_allowed, safe_mmio_read32, safe_mmio_write32, validate_dma_buffer,
    validate_lba_range, validate_mmio_region, validate_pci_access, validate_prp_list, DriverError,
    DriverOpType, RateLimiter,
};
pub use virtio_rng::init_virtio_rng;

// Legacy diagnostics. `critical` and `stats` enumerate the
// audio/gpu/xhci/ahci device set; they cannot exist without the
// drivers behind them. Off in microkernel.
#[cfg(feature = "nonos-legacy-tree")]
mod critical;
#[cfg(feature = "nonos-legacy-tree")]
mod stats;
#[cfg(feature = "nonos-legacy-tree")]
pub use critical::{get_critical_drivers, CriticalDriver, DriverType, SecurityLevel};
#[cfg(feature = "nonos-legacy-tree")]
pub use stats::{get_hardware_stats, HardwareStats};

// Legacy hardware stack. Storage controllers, network NICs, USB,
// audio, GPU, TPM, I2C, the legacy console, plus the orchestrators
// that drive them. Off in every microkernel profile. These are the
// drivers slated for capsule migration or deletion.
#[cfg(feature = "nonos-legacy-tree")]
pub mod ahci;
#[cfg(feature = "nonos-legacy-tree")]
pub mod audio;
#[cfg(feature = "nonos-legacy-tree")]
pub mod block;
#[cfg(all(feature = "nonos-legacy-tree", target_arch = "x86_64"))]
pub mod console;
#[cfg(feature = "nonos-legacy-tree")]
pub mod e1000;
#[cfg(all(feature = "nonos-legacy-tree", feature = "nonos-fbcon"))]
pub mod fbcon;
#[cfg(feature = "nonos-legacy-tree")]
pub mod gpu;
#[cfg(feature = "nonos-legacy-tree")]
pub mod i2c;
#[cfg(feature = "nonos-legacy-tree")]
mod init;
#[cfg(feature = "nonos-legacy-tree")]
pub mod init_dma;
#[cfg(feature = "nonos-legacy-tree")]
pub mod init_network;
#[cfg(feature = "nonos-legacy-tree")]
pub mod init_peripherals;
#[cfg(feature = "nonos-legacy-tree")]
pub mod init_storage;
#[cfg(all(feature = "nonos-legacy-tree", target_arch = "x86_64"))]
pub mod keyboard;
#[cfg(feature = "nonos-legacy-tree")]
pub mod keyboard_buffer;
#[cfg(feature = "nonos-legacy-tree")]
pub mod monster;
#[cfg(feature = "nonos-legacy-tree")]
pub mod network;
#[cfg(feature = "nonos-legacy-tree")]
pub mod nvme;
#[cfg(all(feature = "nonos-legacy-tree", target_arch = "x86_64"))]
pub mod rtl8139;
#[cfg(feature = "nonos-legacy-tree")]
pub mod rtl8168;
#[cfg(feature = "nonos-legacy-tree")]
pub mod tpm;
#[cfg(feature = "nonos-legacy-tree")]
pub mod usb;
#[cfg(all(feature = "nonos-legacy-tree", target_arch = "x86_64"))]
pub mod vga;
#[cfg(feature = "nonos-legacy-tree")]
pub mod virtio_blk;
#[cfg(feature = "nonos-legacy-tree")]
pub mod virtio_net;
#[cfg(feature = "nonos-legacy-tree")]
pub mod wifi;
#[cfg(feature = "nonos-legacy-tree")]
pub mod xhci;

#[cfg(feature = "nonos-legacy-tree")]
mod exports;
#[cfg(feature = "nonos-legacy-tree")]
pub use crate::arch::x86_64::pci::{DmaDescriptor, DmaEngine, MsixCapability, MsixTableEntry};
#[cfg(feature = "nonos-legacy-tree")]
pub use audio::{
    get_controller as get_audio_controller, init_hd_audio, AudioError, AudioFormat, AudioStats,
    HdAudioController,
};
#[cfg(feature = "nonos-legacy-tree")]
pub use block::{is_open, open_count};
#[cfg(feature = "nonos-legacy-tree")]
pub use exports::*;
#[cfg(feature = "nonos-legacy-tree")]
pub use gpu::{
    init_gpu, with_driver as with_gpu_driver, DisplayMode, GpuDriver, GpuStats, GpuSurface,
    PixelFormat,
};
#[cfg(feature = "nonos-legacy-tree")]
pub use i2c::{
    controller_count as i2c_controller_count, get_controller as get_i2c_controller,
    init as init_i2c, read as i2c_read, write as i2c_write, write_read as i2c_write_read,
    DesignWareI2c, I2cAddress, I2cError, I2cSpeed, LpssController,
};
#[cfg(feature = "nonos-legacy-tree")]
pub use init::init_all_drivers;
#[cfg(feature = "nonos-legacy-tree")]
pub use init_dma::init_dma_subsystem;
#[cfg(feature = "nonos-legacy-tree")]
pub use init_network::init_network_drivers;
#[cfg(feature = "nonos-legacy-tree")]
pub use init_peripherals::init_peripheral_drivers;
#[cfg(feature = "nonos-legacy-tree")]
pub use init_storage::init_storage_drivers;
