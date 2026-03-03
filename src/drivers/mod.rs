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
pub mod console;
mod critical;
mod device_info;
pub mod e1000;
pub mod gpu;
pub mod i2c;
mod init;
pub mod keyboard;
pub mod keyboard_buffer;
pub mod monster;
pub mod network;
pub mod nvme;
pub mod pci;
pub mod rtl8139;
pub mod rtl8168;
pub mod security;
mod stats;
pub mod tpm;
pub mod usb;
pub mod vga;
pub mod virtio_net;
pub mod wifi;
pub mod xhci;

pub use security::{
    is_config_write_allowed, safe_mmio_read32, safe_mmio_write32, validate_dma_buffer,
    validate_lba_range, validate_mmio_region, validate_pci_access, validate_prp_list,
    DriverError, DriverOpType, RateLimiter,
};

pub use pci::{get_pci_manager, init_pci, PciBar, PciCapability, PciDevice, PciManager, PciStats};

pub use crate::arch::x86_64::pci::{DmaDescriptor, DmaEngine, MsixCapability, MsixTableEntry};

pub use nvme::{
    get_controller as get_nvme_controller, init_nvme, Namespace as NvmeNamespace, NvmeCompletion,
    NvmeController, NvmeDriver, NvmeError, NvmeSecurityStats, NvmeStatsSnapshot as NvmeStats,
};

pub use ahci::{
    get_controller as get_ahci_controller, init_ahci, AhciController, AhciDevice, AhciDeviceType,
    AhciError, AhciStats,
};

pub use xhci::{get_controller as get_xhci_controller, init_xhci, XhciController, XhciStats};

pub use audio::{
    get_controller as get_audio_controller, init_hd_audio, AudioError, AudioFormat, AudioStats,
    HdAudioController,
};

pub use gpu::{
    init_gpu, with_driver as with_gpu_driver, DisplayMode, GpuDriver, GpuStats, GpuSurface,
    PixelFormat,
};

pub use virtio_net::{
    get_virtio_net_device, init_virtio_net, NetworkStats, NetworkStatsSnapshot, VirtioNetDevice,
    VirtioNetError, VirtioNetHeader, VirtioNetInterface,
};

pub use e1000::{
    get_e1000_device, get_stats as get_e1000_stats, init_e1000, is_present as e1000_is_present,
    E1000Device, E1000Stats,
};

pub use rtl8139::{
    get_rtl8139_device, get_stats as get_rtl8139_stats,
    handle_interrupt as rtl8139_handle_interrupt, init_rtl8139, is_present as rtl8139_is_present,
    Rtl8139Device, Rtl8139Stats,
};

pub use rtl8168::{
    get_rtl8168_device, get_stats as get_rtl8168_stats,
    handle_interrupt as rtl8168_handle_interrupt, init_rtl8168, is_present as rtl8168_is_present,
    Rtl8168Device, Rtl8168Stats,
};

pub use wifi::{
    connect as wifi_connect, device_count as wifi_device_count, disconnect as wifi_disconnect,
    get_device as get_wifi_device, get_realtek_device as get_realtek_wifi_device,
    init as init_wifi, is_available as wifi_is_available, is_connected as wifi_is_connected,
    is_realtek as wifi_is_realtek, load_firmware_from_disk as wifi_load_firmware,
    print_status as print_wifi_status, scan as wifi_scan, try_load_firmware as wifi_try_load_firmware,
    IntelWifiDevice, LinkInfo, RealtekWifiDevice, ScanConfig, ScanResult, WifiError, WifiState,
};

pub use tpm::{
    create_quote, extend_pcr_sha256, get_measurement_log, get_random_bytes as tpm_get_random_bytes,
    get_tpm_status, init_tpm, is_tpm_available, measure_component, measure_config_change,
    measure_module, read_pcr, shutdown_tpm, verify_boot_chain, BootChainMeasurements,
    ComponentType, PcrMeasurement, TpmError, TpmResult, TpmStatus,
};

pub use critical::{get_critical_drivers, CriticalDriver, DriverType, SecurityLevel};
pub use device_info::{get_all_devices, DeviceInfo, SecurityStatus};
pub use init::init_all_drivers;
pub use stats::{get_hardware_stats, HardwareStats};

pub use i2c::{
    controller_count as i2c_controller_count, get_controller as get_i2c_controller,
    init as init_i2c, read as i2c_read, write as i2c_write, write_read as i2c_write_read,
    DesignWareI2c, I2cAddress, I2cError, I2cSpeed, LpssController,
};
