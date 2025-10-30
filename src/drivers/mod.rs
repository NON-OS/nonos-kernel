//! Device Drivers Module

use alloc::collections::BTreeMap;

pub mod nonos_keyboard;
pub mod nonos_vga;
pub mod nonos_pci;
pub mod nonos_nvme;
pub mod nonos_ahci;         // Advanced SATA controller
pub mod nonos_xhci;         // USB 3.0 controller
pub mod nonos_audio;        // HD Audio controller
pub mod nonos_gpu;          // Graphics processing unit
pub mod nonos_virtio_net;   // VirtIO network driver
pub mod nonos_network;      // Network driver interface
pub mod nonos_usb;          // USB host/controller manager
pub mod nonos_console;      // Console driver with VGA/serial
pub mod nonos_monster;      // MONSTER driver orchestrator and health manager

// Re-exports for backward compatibility
pub use nonos_keyboard as keyboard;
pub use nonos_vga as vga;
pub use nonos_pci as pci;
pub use nonos_nvme as nvme;
pub use nonos_ahci as ahci;
pub use nonos_xhci as xhci;
pub use nonos_audio as audio;
pub use nonos_gpu as gpu;
pub use nonos_virtio_net as virtio_net;
pub use nonos_network as network;
pub use nonos_usb as usb;
pub use nonos_console as console;
// Convenience alias for MONSTER orchestrator
pub use nonos_monster as monster;

pub use nonos_pci::{
    PciManager, PciDevice, PciBar, PciCapability, init_pci, get_pci_manager
};

pub use crate::arch::x86_64::nonos_pci::{
    DmaEngine, DmaDescriptor, MsixCapability, MsixTableEntry, PciStats
};

pub use nonos_nvme::{
    NvmeDriver, NvmeCompletion, NvmeController, NvmeNamespace, NvmeStats
};

pub use nonos_ahci::{
    AhciController, AhciDevice, AhciDeviceType, AhciStats,
    init_ahci, get_controller as get_ahci_controller
};

pub use nonos_xhci::{
    XhciController, XhciStats,
    init_xhci, get_controller as get_xhci_controller
};

pub use nonos_audio::{
    HdAudioController, AudioStats,
    init_hd_audio, get_controller as get_audio_controller
};

pub use nonos_gpu::{
    GpuDriver, DisplayMode, PixelFormat, GpuSurface, GpuStats,
    init_gpu, with_driver as with_gpu_driver
};

pub use nonos_virtio_net::{
    VirtioNetDevice, VirtioNetInterface, init_virtio_net, get_virtio_net_device
};

/// Initialize all hardware drivers
pub fn init_all_drivers() -> Result<(), &'static str> {
    crate::memory::dma::init_dma_allocator()?;
    let _ = crate::memory::dma::create_dma_pool(4096, 128, crate::memory::dma::DmaConstraints::default());
    let _ = crate::memory::dma::create_dma_pool(2048, 256, crate::memory::dma::DmaConstraints::default());

    crate::log::logger::log_critical("Initializing NONOS driver stack via MONSTER orchestrator...");
    // Delegate to MONSTER (handles PCI, NVMe, xHCI+USB, VirtIO, GPU, Audio).
    nonos_monster::monster_init()?;
    crate::log::logger::log_critical("✓ NONOS driver stack initialized");

    Ok(())
}

/// Get comprehensive system hardware statistics
pub fn get_hardware_stats() -> HardwareStats {
    HardwareStats {
        pci_stats: get_pci_manager().map(|mgr| mgr.get_stats()).unwrap_or_default(),
        nvme_stats: nonos_nvme::get_controller().map(|ctrl| ctrl.get_stats()).unwrap_or_default(),
        ahci_stats: get_ahci_controller().map(|ctrl| ctrl.get_stats()).unwrap_or_default(),
        xhci_stats: get_xhci_controller().map(|ctrl| ctrl.get_stats()).unwrap_or_default(),
        audio_stats: get_audio_controller().map(|ctrl| ctrl.get_stats()).unwrap_or_default(),
        gpu_stats: with_gpu_driver(|drv| drv.get_stats()).unwrap_or_default(),
    }
}

/// Comprehensive hardware statistics
pub struct HardwareStats {
    pub pci_stats: PciStats,
    pub nvme_stats: NvmeStats,
    pub ahci_stats: AhciStats,
    pub xhci_stats: XhciStats,
    pub audio_stats: AudioStats,
    pub gpu_stats: GpuStats,
}

impl Default for HardwareStats {
    fn default() -> Self {
        Self {
            pci_stats: PciStats {
                total_devices: 0,
                devices_by_class: BTreeMap::new(),
                msix_devices: 0,
                dma_engines: 0,
                devices_found: 0,
                dma_transfers: 0,
                interrupts_handled: 0,
                errors: 0,
            },
            nvme_stats: NvmeStats { commands_completed: 0, bytes_read: 0, bytes_written: 0, errors: 0, namespaces: 0 },
            ahci_stats: AhciStats { read_ops: 0, write_ops: 0, trim_ops: 0, errors: 0, bytes_read: 0, bytes_written: 0, devices_count: 0 },
            xhci_stats: XhciStats { transfers: 0, errors: 0, interrupts: 0, bytes_transferred: 0, devices_connected: 0, max_slots: 0, max_ports: 0 },
            audio_stats: AudioStats { samples_played: 0, samples_recorded: 0, buffer_underruns: 0, buffer_overruns: 0, interrupts_handled: 0, active_streams: 0, codecs_detected: 0 },
            gpu_stats: GpuStats { frames_rendered: 0, commands_executed: 0, memory_allocated: 0, gpu_errors: 0, surfaces_created: 0, shaders_loaded: 0, vendor_id: 0, device_id: 0 },
        }
    }
}

/// Critical driver information for security monitoring
#[derive(Debug, Clone)]
pub struct CriticalDriver {
    pub name: &'static str,
    pub driver_type: DriverType,
    pub base_address: usize,
    pub size: usize,
    pub hash: [u8; 32],
    pub version: u32,
    pub security_level: SecurityLevel,
}

#[derive(Debug, Clone)]
pub enum DriverType {
    Storage,
    Network,
    Crypto,
    Security,
    System,
}

#[derive(Debug, Clone)]
pub enum SecurityLevel {
    Critical,   // Kernel core, crypto, security
    High,       // Storage, network
    Medium,     // Audio, graphics
    Low,        // Input devices
}

/// Get list of critical drivers for security monitoring
pub fn get_critical_drivers() -> alloc::vec::Vec<CriticalDriver> {
    use alloc::vec::Vec;

    let mut drivers = Vec::new();

    // Add AHCI controller as critical storage driver
    if let Some(ahci_ctrl) = get_ahci_controller() {
        drivers.push(CriticalDriver {
            name: "AHCI Storage Controller",
            driver_type: DriverType::Storage,
            base_address: ahci_ctrl as *const _ as usize,
            size: core::mem::size_of_val(ahci_ctrl),
            hash: crate::crypto::blake3::blake3_hash(unsafe {
                core::slice::from_raw_parts(
                    ahci_ctrl as *const _ as *const u8,
                    core::mem::size_of_val(ahci_ctrl)
                )
            }),
            version: 1,
            security_level: SecurityLevel::Critical,
        });
    }

    // Add NVMe controller as critical storage driver
    if let Some(nvme_ctrl) = nonos_nvme::get_controller() {
        drivers.push(CriticalDriver {
            name: "NVMe Storage Controller",
            driver_type: DriverType::Storage,
            base_address: &*nvme_ctrl as *const _ as usize,
            size: core::mem::size_of_val(&nvme_ctrl),
            hash: crate::crypto::blake3::blake3_hash(unsafe {
                core::slice::from_raw_parts(
                    &*nvme_ctrl as *const _ as *const u8,
                    core::mem::size_of_val(&nvme_ctrl)
                )
            }),
            version: 1,
            security_level: SecurityLevel::Critical,
        });
    }

    // Add PCI manager as system driver
    if let Some(pci_mgr) = get_pci_manager() {
        drivers.push(CriticalDriver {
            name: "PCI Bus Manager",
            driver_type: DriverType::System,
            base_address: pci_mgr as *const _ as usize,
            size: core::mem::size_of_val(pci_mgr),
            hash: crate::crypto::blake3::blake3_hash(unsafe {
                core::slice::from_raw_parts(
                    pci_mgr as *const _ as *const u8,
                    core::mem::size_of_val(pci_mgr)
                )
            }),
            version: 1,
            security_level: SecurityLevel::Critical,
        });
    }

    drivers
}

/// Device information for monitoring and security
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub name: &'static str,
    pub device_type: DriverType,
    pub vendor_id: u16,
    pub device_id: u16,
    pub address: usize,
    pub size: usize,
    pub capabilities: u32,
    pub security_status: SecurityStatus,
}

#[derive(Debug, Clone)]
pub enum SecurityStatus {
    Verified,    // Device has valid signature
    Unverified,  // Device not yet checked
    Suspicious,  // Device failed some checks
    Blocked,     // Device blocked by security policy
}

/// Get all hardware devices for security scanning
pub fn get_all_devices() -> alloc::vec::Vec<DeviceInfo> {
    use alloc::vec::Vec;

    let mut devices = Vec::new();

    // Scan PCI bus for all devices
    if let Some(pci_manager) = get_pci_manager() {
        let pci_devices = pci_manager.enumerate_all_devices();

        for pci_dev in pci_devices {
            devices.push(DeviceInfo {
                name: match (pci_dev.vendor_id, pci_dev.device_id) {
                    (0x8086, _) => "Intel Device",
                    (0x1022, _) => "AMD Device",
                    (0x10DE, _) => "NVIDIA Device",
                    (0x1234, 0x1111) => "QEMU VGA",
                    (0x1AF4, _) => "VirtIO Device",
                    _ => "Unknown Device",
                },
                device_type: classify_device_type(pci_dev.class as u32),
                vendor_id: pci_dev.vendor_id,
                device_id: pci_dev.device_id,
                address: pci_dev.bars[0].as_ref().map(|bar| match bar {
                    crate::drivers::pci::PciBar::Memory { address, .. } => address.as_u64() as usize,
                    crate::drivers::pci::PciBar::Io { port, .. } => *port as usize,
                }).unwrap_or(0),
                size: pci_dev.bars[0].as_ref().map(|bar| match bar {
                    crate::drivers::pci::PciBar::Memory { size, .. } => *size,
                    crate::drivers::pci::PciBar::Io { size, .. } => *size,
                }).unwrap_or(0),
                capabilities: pci_dev.capabilities.iter().fold(0u32, |acc, cap| {
                    acc | match cap.id {
                        0x01 => 0x01, // Power Management
                        0x05 => 0x02, // MSI
                        0x10 => 0x04, // PCIe
                        0x11 => 0x08, // MSI-X
                        _ => 0x00,
                    }
                }),
                security_status: SecurityStatus::Verified, // To be verified once shift to real system
            });
        }
    }

    // Add virtual/platform devices
    devices.push(DeviceInfo {
        name: "System Timer",
        device_type: DriverType::System,
        vendor_id: 0,
        device_id: 0,
        address: 0,
        size: 0,
        capabilities: 0,
        security_status: SecurityStatus::Verified,
    });

    devices.push(DeviceInfo {
        name: "Interrupt Controller",
        device_type: DriverType::System,
        vendor_id: 0,
        device_id: 0,
        address: 0,
        size: 0,
        capabilities: 0,
        security_status: SecurityStatus::Verified,
    });

    devices
}

/// Classify PCI device type based on class code
fn classify_device_type(class_code: u32) -> DriverType {
    match (class_code >> 16) & 0xFF {
        0x01 => DriverType::Storage,    // Mass Storage Controller
        0x02 => DriverType::Network,    // Network Controller
        0x03 => DriverType::System,     // Display Controller
        0x04 => DriverType::System,     // Multimedia Controller
        0x0C => match (class_code >> 8) & 0xFF {
            0x03 => DriverType::System, // USB Controller
            _ => DriverType::System,
        },
        0x10 => DriverType::Crypto,     // Encryption Controller
        _ => DriverType::System,
    }
}

/// Compatibility functions for keyboard buffer
pub mod keyboard_buffer {
    use alloc::collections::VecDeque;
    use spin::Mutex;

    static KEYBOARD_BUFFER: Mutex<VecDeque<char>> = Mutex::new(VecDeque::new());

    /// Add character to keyboard buffer
    pub fn add_to_buffer(ch: char) {
        let mut buffer = KEYBOARD_BUFFER.lock();
        buffer.push_back(ch);

        // Limit buffer size
        if buffer.len() > 256 {
            buffer.pop_front();
        }
    }

    /// Read character from keyboard buffer
    pub fn read_char() -> Option<char> {
        let mut buffer = KEYBOARD_BUFFER.lock();
        buffer.pop_front()
    }

    /// Check if buffer has data
    pub fn has_data() -> bool {
        let buffer = KEYBOARD_BUFFER.lock();
        !buffer.is_empty()
    }
}
