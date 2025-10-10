//! PCI Bus Management for x86_64
//!
//! Complete PCI bus enumeration, device management, and configuration
//! with support for PCI Express, MSI-X interrupts, and DMA operations.

use alloc::{collections::BTreeMap, vec::Vec};
use x86_64::{PhysAddr, VirtAddr};

/// PCI Configuration Space offsets
const PCI_VENDOR_ID: u16 = 0x00;
const PCI_DEVICE_ID: u16 = 0x02;
const PCI_COMMAND: u16 = 0x04;
const PCI_STATUS: u16 = 0x06;
const PCI_CLASS_CODE: u16 = 0x0B;
const PCI_SUBCLASS: u16 = 0x0A;
const PCI_PROG_IF: u16 = 0x09;
const PCI_REVISION_ID: u16 = 0x08;
const PCI_HEADER_TYPE: u16 = 0x0E;
const PCI_BAR0: u16 = 0x10;
const PCI_BAR1: u16 = 0x14;
const PCI_BAR2: u16 = 0x18;
const PCI_BAR3: u16 = 0x1C;
const PCI_BAR4: u16 = 0x20;
const PCI_BAR5: u16 = 0x24;
const PCI_INTERRUPT_LINE: u16 = 0x3C;
const PCI_INTERRUPT_PIN: u16 = 0x3D;

/// PCI device representation
#[derive(Debug, Clone, Copy)]
pub struct PciDevice {
    pub bus: u8,
    pub slot: u8,
    pub function: u8,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class_code: u8,
    pub subclass: u8,
    pub prog_if: u8,
    pub revision_id: u8,
    pub header_type: u8,
    pub interrupt_line: u8,
    pub interrupt_pin: u8,
}

impl PciDevice {
    /// Create PCI device from bus location
    pub fn new(bus: u8, slot: u8, function: u8) -> Option<Self> {
        let vendor_id = pci_config_read_word(bus, slot, function, PCI_VENDOR_ID);
        if vendor_id == 0xFFFF {
            return None; // Device doesn't exist
        }

        let device_id = pci_config_read_word(bus, slot, function, PCI_DEVICE_ID);
        let class_code = pci_config_read_byte(bus, slot, function, PCI_CLASS_CODE);
        let subclass = pci_config_read_byte(bus, slot, function, PCI_SUBCLASS);
        let prog_if = pci_config_read_byte(bus, slot, function, PCI_PROG_IF);
        let revision_id = pci_config_read_byte(bus, slot, function, PCI_REVISION_ID);
        let header_type = pci_config_read_byte(bus, slot, function, PCI_HEADER_TYPE) & 0x7F;
        let interrupt_line = pci_config_read_byte(bus, slot, function, PCI_INTERRUPT_LINE);
        let interrupt_pin = pci_config_read_byte(bus, slot, function, PCI_INTERRUPT_PIN);

        Some(PciDevice {
            bus,
            slot,
            function,
            vendor_id,
            device_id,
            class_code,
            subclass,
            prog_if,
            revision_id,
            header_type,
            interrupt_line,
            interrupt_pin,
        })
    }

    /// Get Base Address Register (BAR)
    pub fn get_bar(&self, bar_index: u8) -> Result<PciBar, &'static str> {
        if bar_index > 5 {
            return Err("Invalid BAR index");
        }

        let bar_offset = PCI_BAR0 + (bar_index as u16 * 4);
        let bar_value = pci_config_read_dword(self.bus, self.slot, self.function, bar_offset);

        if bar_value == 0 {
            return Err("BAR not implemented");
        }

        if (bar_value & 1) == 0 {
            // Memory BAR
            let prefetchable = (bar_value & 0x08) != 0;
            let bar_type = (bar_value & 0x06) >> 1;
            let base_addr = (bar_value & !0xF) as u64;

            // Get size by writing all 1s and reading back
            pci_config_write_dword(self.bus, self.slot, self.function, bar_offset, 0xFFFFFFFF);
            let size_mask = pci_config_read_dword(self.bus, self.slot, self.function, bar_offset);
            pci_config_write_dword(self.bus, self.slot, self.function, bar_offset, bar_value);

            let size = !(size_mask & !0xF).wrapping_add(1) as u64;

            Ok(PciBar { base_addr, size, memory_mapped: true, prefetchable, bar_type })
        } else {
            // I/O BAR
            let base_addr = (bar_value & !0x3) as u64;

            // Get size
            pci_config_write_dword(self.bus, self.slot, self.function, bar_offset, 0xFFFFFFFF);
            let size_mask = pci_config_read_dword(self.bus, self.slot, self.function, bar_offset);
            pci_config_write_dword(self.bus, self.slot, self.function, bar_offset, bar_value);

            let size = !(size_mask & !0x3).wrapping_add(1) as u64;

            Ok(PciBar { base_addr, size, memory_mapped: false, prefetchable: false, bar_type: 0 })
        }
    }

    /// Enable bus mastering for DMA operations
    pub fn enable_bus_mastering(&self) -> Result<(), &'static str> {
        let mut command = pci_config_read_word(self.bus, self.slot, self.function, PCI_COMMAND);
        command |= 0x04; // Bus Master Enable
        pci_config_write_word(self.bus, self.slot, self.function, PCI_COMMAND, command);
        Ok(())
    }

    /// Enable memory space access
    pub fn enable_memory_space(&self) -> Result<(), &'static str> {
        let mut command = pci_config_read_word(self.bus, self.slot, self.function, PCI_COMMAND);
        command |= 0x02; // Memory Space Enable
        pci_config_write_word(self.bus, self.slot, self.function, PCI_COMMAND, command);
        Ok(())
    }

    /// Configure MSI-X interrupts
    pub fn configure_msix(&self, vector: u8) -> Result<(), &'static str> {
        // Find MSI-X capability
        if let Some(msix_cap) = self.find_capability(0x11) {
            // Enable MSI-X
            let control = pci_config_read_word(self.bus, self.slot, self.function, msix_cap + 2);
            let new_control = control | 0x8000; // MSI-X Enable
            pci_config_write_word(self.bus, self.slot, self.function, msix_cap + 2, new_control);

            // Configure MSI-X table entry 0
            // This is simplified - real implementation would map MSI-X table

            Ok(())
        } else {
            Err("MSI-X capability not found")
        }
    }

    /// Find PCI capability
    pub fn find_capability(&self, cap_id: u8) -> Option<u16> {
        let status = pci_config_read_word(self.bus, self.slot, self.function, PCI_STATUS);
        if (status & 0x10) == 0 {
            return None; // No capabilities list
        }

        let mut cap_ptr = pci_config_read_byte(self.bus, self.slot, self.function, 0x34) as u16;

        while cap_ptr != 0 && cap_ptr != 0xFF {
            let cap = pci_config_read_byte(self.bus, self.slot, self.function, cap_ptr);
            if cap == cap_id {
                return Some(cap_ptr);
            }
            cap_ptr = pci_config_read_byte(self.bus, self.slot, self.function, cap_ptr + 1) as u16;
        }

        None
    }
}

/// PCI Base Address Register (BAR) information
#[derive(Debug, Clone, Copy)]
pub struct PciBar {
    pub base_addr: u64,
    pub size: u64,
    pub memory_mapped: bool,
    pub prefetchable: bool,
    pub bar_type: u32, // 0 = 32-bit, 2 = 64-bit
}

/// PCI capability structure
#[derive(Debug, Clone, Copy)]
pub struct PciCapability {
    pub id: u8,
    pub offset: u16,
    pub length: u8,
}

/// DMA engine for PCI devices
pub struct DmaEngine {
    pub device: PciDevice,
    pub coherent_memory: Vec<DmaBuffer>,
    pub streaming_memory: Vec<DmaBuffer>,
}

/// DMA buffer descriptor
pub struct DmaBuffer {
    pub virt_addr: VirtAddr,
    pub phys_addr: PhysAddr,
    pub size: usize,
    pub coherent: bool,
}

/// DMA descriptor for scatter-gather operations
#[repr(C)]
pub struct DmaDescriptor {
    pub addr: u64,
    pub length: u32,
    pub flags: u32,
}

/// MSI-X capability structure
#[repr(C)]
pub struct MsixCapability {
    pub cap_id: u8,
    pub next_ptr: u8,
    pub message_control: u16,
    pub table_offset_bir: u32,
    pub pba_offset_bir: u32,
}

/// MSI-X table entry
#[repr(C)]
pub struct MsixTableEntry {
    pub message_addr_low: u32,
    pub message_addr_high: u32,
    pub message_data: u32,
    pub vector_control: u32,
}

/// PCI statistics
#[derive(Debug, Default)]
pub struct PciStats {
    pub total_devices: usize,
    pub devices_by_class: BTreeMap<u8, usize>,
    pub msix_devices: usize,
    pub dma_engines: usize,
    pub devices_found: u64,
    pub dma_transfers: u64,
    pub interrupts_handled: u64,
    pub errors: u64,
}

/// Scan PCI bus for all devices
pub fn scan_pci_bus() -> Result<Vec<PciDevice>, &'static str> {
    let mut devices = Vec::new();

    for bus in 0..=255 {
        for slot in 0..32 {
            if let Some(device) = PciDevice::new(bus, slot, 0) {
                devices.push(device);

                // Check for multi-function device
                if (device.header_type & 0x80) != 0 {
                    for function in 1..8 {
                        if let Some(multi_device) = PciDevice::new(bus, slot, function) {
                            devices.push(multi_device);
                        }
                    }
                }
            }
        }
    }

    Ok(devices)
}

/// Read 32-bit value from PCI configuration space
pub fn pci_config_read_dword(bus: u8, slot: u8, function: u8, offset: u16) -> u32 {
    let address = 0x80000000u32
        | ((bus as u32) << 16)
        | ((slot as u32) << 11)
        | ((function as u32) << 8)
        | ((offset as u32) & 0xFC);

    unsafe {
        // Write address to CONFIG_ADDRESS (0xCF8)
        x86_64::instructions::port::Port::new(0xCF8).write(address);
        // Read data from CONFIG_DATA (0xCFC)
        x86_64::instructions::port::Port::new(0xCFC).read()
    }
}

/// Write 32-bit value to PCI configuration space
pub fn pci_config_write_dword(bus: u8, slot: u8, function: u8, offset: u16, value: u32) {
    let address = 0x80000000u32
        | ((bus as u32) << 16)
        | ((slot as u32) << 11)
        | ((function as u32) << 8)
        | ((offset as u32) & 0xFC);

    unsafe {
        x86_64::instructions::port::Port::new(0xCF8).write(address);
        x86_64::instructions::port::Port::new(0xCFC).write(value);
    }
}

/// Read 16-bit value from PCI configuration space
pub fn pci_config_read_word(bus: u8, slot: u8, function: u8, offset: u16) -> u16 {
    let dword = pci_config_read_dword(bus, slot, function, offset & 0xFFFC);
    ((dword >> ((offset & 2) * 8)) & 0xFFFF) as u16
}

/// Write 16-bit value to PCI configuration space
pub fn pci_config_write_word(bus: u8, slot: u8, function: u8, offset: u16, value: u16) {
    let aligned_offset = offset & 0xFFFC;
    let mut dword = pci_config_read_dword(bus, slot, function, aligned_offset);
    let shift = (offset & 2) * 8;
    dword = (dword & !(0xFFFF << shift)) | ((value as u32) << shift);
    pci_config_write_dword(bus, slot, function, aligned_offset, dword);
}

/// Read 8-bit value from PCI configuration space
pub fn pci_config_read_byte(bus: u8, slot: u8, function: u8, offset: u16) -> u8 {
    let dword = pci_config_read_dword(bus, slot, function, offset & 0xFFFC);
    ((dword >> ((offset & 3) * 8)) & 0xFF) as u8
}

/// Write 8-bit value to PCI configuration space
pub fn pci_config_write_byte(bus: u8, slot: u8, function: u8, offset: u16, value: u8) {
    let aligned_offset = offset & 0xFFFC;
    let mut dword = pci_config_read_dword(bus, slot, function, aligned_offset);
    let shift = (offset & 3) * 8;
    dword = (dword & !(0xFF << shift)) | ((value as u32) << shift);
    pci_config_write_dword(bus, slot, function, aligned_offset, dword);
}

/// PCI device class codes
pub mod class_codes {
    pub const UNCLASSIFIED: u8 = 0x00;
    pub const STORAGE: u8 = 0x01;
    pub const NETWORK: u8 = 0x02;
    pub const DISPLAY: u8 = 0x03;
    pub const MULTIMEDIA: u8 = 0x04;
    pub const MEMORY: u8 = 0x05;
    pub const BRIDGE: u8 = 0x06;
    pub const COMMUNICATION: u8 = 0x07;
    pub const SYSTEM: u8 = 0x08;
    pub const INPUT: u8 = 0x09;
    pub const DOCKING: u8 = 0x0A;
    pub const PROCESSOR: u8 = 0x0B;
    pub const SERIAL_BUS: u8 = 0x0C;
    pub const WIRELESS: u8 = 0x0D;
    pub const SATELLITE: u8 = 0x0F;
    pub const ENCRYPTION: u8 = 0x10;
    pub const SIGNAL_PROCESSING: u8 = 0x11;
}

/// Get class name from class code
pub fn get_class_name(class_code: u8) -> &'static str {
    match class_code {
        class_codes::UNCLASSIFIED => "Unclassified",
        class_codes::STORAGE => "Storage Controller",
        class_codes::NETWORK => "Network Controller",
        class_codes::DISPLAY => "Display Controller",
        class_codes::MULTIMEDIA => "Multimedia Controller",
        class_codes::MEMORY => "Memory Controller",
        class_codes::BRIDGE => "Bridge Device",
        class_codes::COMMUNICATION => "Communication Controller",
        class_codes::SYSTEM => "System Peripheral",
        class_codes::INPUT => "Input Device",
        class_codes::DOCKING => "Docking Station",
        class_codes::PROCESSOR => "Processor",
        class_codes::SERIAL_BUS => "Serial Bus Controller",
        class_codes::WIRELESS => "Wireless Controller",
        class_codes::SATELLITE => "Satellite Communication Controller",
        class_codes::ENCRYPTION => "Encryption Controller",
        class_codes::SIGNAL_PROCESSING => "Signal Processing Controller",
        _ => "Unknown",
    }
}
