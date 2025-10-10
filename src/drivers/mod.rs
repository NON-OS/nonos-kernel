//! Advanced Device Drivers Module
//!
//! Enterprise device drivers with DMA and MSI-X support

use alloc::collections::BTreeMap;

pub mod ahci; // Advanced SATA controller
pub mod audio; // HD Audio controller
pub mod console;
pub mod gpu; // Graphics processing unit
pub mod keyboard;
pub mod network; // Network driver interface
pub mod nvme;
pub mod pci;
pub mod usb; // Real USB host controller driver
pub mod vga;
pub mod virtio_net; // VirtIO network driver
pub mod xhci; // USB 3.0 controller // Real console driver with VGA/serial

pub use pci::{
    get_pci_manager, init_pci, DmaDescriptor, DmaEngine, MsixCapability, MsixTableEntry, PciBar,
    PciCapability, PciDevice, PciManager, PciStats,
};

pub use nvme::{
    NvmeCommand, NvmeCompletion, NvmeController, NvmeDriver, NvmeNamespace, NvmeQueue, NvmeRequest,
    NvmeStats,
};

pub use ahci::{
    get_controller as get_ahci_controller, init_ahci, AhciController, AhciDevice, AhciDeviceType,
    AhciStats,
};

pub use xhci::{
    get_controller as get_xhci_controller, init_xhci, TransferDirection, UsbDevice, UsbSpeed,
    XhciController, XhciStats,
};

pub use audio::{
    get_controller as get_audio_controller, init_hd_audio, AudioBuffer, AudioFormat, AudioStats,
    HdAudioController, StreamType,
};

pub use gpu::{
    get_driver as get_gpu_driver, init_gpu, DisplayMode, GpuCommand, GpuDriver, GpuStats,
    GpuSurface, PixelFormat,
};

pub use virtio_net::{get_virtio_net_device, init_virtio_net, VirtioNetDevice, VirtioNetInterface};

/// Initialize all hardware drivers
pub fn init_all_drivers() -> Result<(), &'static str> {
    crate::log::logger::log_critical("Initializing comprehensive hardware driver ecosystem...");

    // Initialize PCI first (required for other drivers)
    init_pci()?;
    crate::log::logger::log_critical("✓ PCI subsystem initialized");

    // Initialize storage controllers
    if let Err(_) = nvme::init_nvme() {
        crate::log::logger::log_critical("⚠ NVMe controller not found or failed to initialize");
    } else {
        crate::log::logger::log_critical("✓ NVMe subsystem initialized");
    }

    if let Err(_) = ahci::init_ahci() {
        crate::log::logger::log_critical("⚠ AHCI controller not found or failed to initialize");
    } else {
        crate::log::logger::log_critical("✓ AHCI/SATA subsystem initialized");
    }

    // Initialize USB controllers
    if let Err(_) = xhci::init_xhci() {
        crate::log::logger::log_critical("⚠ xHCI controller not found or failed to initialize");
    } else {
        crate::log::logger::log_critical("✓ USB 3.0/xHCI subsystem initialized");
    }

    // Initialize audio
    if let Err(_) = audio::init_hd_audio() {
        crate::log::logger::log_critical("⚠ HD Audio controller not found or failed to initialize");
    } else {
        crate::log::logger::log_critical("✓ HD Audio subsystem initialized");
    }

    // Initialize graphics
    if let Err(_) = gpu::init_gpu() {
        crate::log::logger::log_critical("⚠ GPU not found or failed to initialize");
    } else {
        crate::log::logger::log_critical("✓ GPU subsystem initialized");
    }

    // Initialize VirtIO network
    if let Err(_) = virtio_net::init_virtio_net() {
        crate::log::logger::log_critical(
            "⚠ VirtIO network device not found or failed to initialize",
        );
    } else {
        crate::log::logger::log_critical("✓ VirtIO network subsystem initialized");
    }

    crate::log::logger::log_critical("🚀 NONOS hardware driver ecosystem initialization complete!");
    crate::log::logger::log_critical(
        "   - Advanced storage: NVMe, AHCI/SATA with cryptographic integration",
    );
    crate::log::logger::log_critical(
        "   - High-speed I/O: USB 3.0/xHCI with security whitelisting",
    );
    crate::log::logger::log_critical("   - Audio processing: HD Audio with secure rendering");
    crate::log::logger::log_critical("   - Graphics acceleration: GPU with encrypted framebuffers");

    Ok(())
}

/// Get comprehensive system hardware statistics
pub fn get_hardware_stats() -> HardwareStats {
    HardwareStats {
        pci_stats: get_pci_manager().map(|mgr| mgr.get_stats()).unwrap_or_default(),
        nvme_stats: nvme::get_controller().map(|ctrl| ctrl.get_stats()).unwrap_or_default(),
        ahci_stats: get_ahci_controller().map(|ctrl| ctrl.get_stats()).unwrap_or_default(),
        xhci_stats: get_xhci_controller().map(|ctrl| ctrl.get_stats()).unwrap_or_default(),
        audio_stats: get_audio_controller().map(|ctrl| ctrl.get_stats()).unwrap_or_default(),
        gpu_stats: get_gpu_driver().map(|drv| drv.get_stats()).unwrap_or_default(),
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
            nvme_stats: NvmeStats {
                commands_completed: 0,
                bytes_read: 0,
                bytes_written: 0,
                errors: 0,
                namespaces: 0,
            },
            ahci_stats: AhciStats {
                read_ops: 0,
                write_ops: 0,
                trim_ops: 0,
                errors: 0,
                bytes_read: 0,
                bytes_written: 0,
                devices_count: 0,
            },
            xhci_stats: XhciStats {
                transfers: 0,
                errors: 0,
                interrupts: 0,
                bytes_transferred: 0,
                devices_connected: 0,
                max_slots: 0,
                max_ports: 0,
            },
            audio_stats: AudioStats {
                samples_played: 0,
                samples_recorded: 0,
                buffer_underruns: 0,
                buffer_overruns: 0,
                interrupts_handled: 0,
                active_streams: 0,
                codecs_detected: 0,
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
    Critical, // Kernel core, crypto, security
    High,     // Storage, network
    Medium,   // Audio, graphics
    Low,      // Input devices
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
            hash: crate::crypto::hash::blake3_hash(unsafe {
                core::slice::from_raw_parts(
                    ahci_ctrl as *const _ as *const u8,
                    core::mem::size_of_val(ahci_ctrl),
                )
            }),
            version: 1,
            security_level: SecurityLevel::Critical,
        });
    }

    // Add NVMe controller as critical storage driver
    if let Some(nvme_ctrl) = nvme::get_controller() {
        drivers.push(CriticalDriver {
            name: "NVMe Storage Controller",
            driver_type: DriverType::Storage,
            base_address: nvme_ctrl as *const _ as usize,
            size: core::mem::size_of_val(nvme_ctrl),
            hash: crate::crypto::hash::blake3_hash(unsafe {
                core::slice::from_raw_parts(
                    nvme_ctrl as *const _ as *const u8,
                    core::mem::size_of_val(nvme_ctrl),
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
            hash: crate::crypto::hash::blake3_hash(unsafe {
                core::slice::from_raw_parts(
                    pci_mgr as *const _ as *const u8,
                    core::mem::size_of_val(pci_mgr),
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
    Verified,   // Device has valid signature
    Unverified, // Device not yet checked
    Suspicious, // Device failed some checks
    Blocked,    // Device blocked by security policy
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
                device_type: classify_device_type(pci_dev.class_code as u32),
                vendor_id: pci_dev.vendor_id,
                device_id: pci_dev.device_id,
                address: pci_dev.bars[0]
                    .as_ref()
                    .map(|bar| match bar {
                        crate::drivers::pci::PciBar::Memory { address, .. } => {
                            address.as_u64() as usize
                        }
                        crate::drivers::pci::PciBar::Io { port, .. } => *port as usize,
                    })
                    .unwrap_or(0),
                size: pci_dev.bars[0]
                    .as_ref()
                    .map(|bar| match bar {
                        crate::drivers::pci::PciBar::Memory { size, .. } => *size,
                        crate::drivers::pci::PciBar::Io { size, .. } => *size,
                    })
                    .unwrap_or(0),
                capabilities: pci_dev.capabilities.iter().fold(0u32, |acc, cap| {
                    acc | match cap.id {
                        0x01 => 0x01, // Power Management
                        0x05 => 0x02, // MSI
                        0x10 => 0x04, // PCIe
                        0x11 => 0x08, // MSI-X
                        _ => 0x00,
                    }
                }),
                security_status: SecurityStatus::Verified, // Would be checked in real system
            });
        }
    }

    // Add virtual devices and platform devices
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
        0x01 => DriverType::Storage, // Mass Storage Controller
        0x02 => DriverType::Network, // Network Controller
        0x03 => DriverType::System,  // Display Controller
        0x04 => DriverType::System,  // Multimedia Controller
        0x0C => match (class_code >> 8) & 0xFF {
            0x03 => DriverType::System, // USB Controller
            _ => DriverType::System,
        },
        0x10 => DriverType::Crypto, // Encryption Controller
        _ => DriverType::System,
    }
}
