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

//! PCI Configuration Space Access
//! Type 1 configuration mechanism (ports 0xCF8/0xCFC)

use crate::sys::io::{inl, outl};
use crate::sys::serial;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// PCI Configuration Address Port
const PCI_CONFIG_ADDRESS: u16 = 0x0CF8;

/// PCI Configuration Data Port
const PCI_CONFIG_DATA: u16 = 0x0CFC;

/// Maximum number of PCI devices we track
const MAX_DEVICES: usize = 64;

/// PCI Initialization flag
static PCI_INIT: AtomicBool = AtomicBool::new(false);

/// Number of devices found
static DEVICE_COUNT: AtomicU32 = AtomicU32::new(0);

/// PCI Device information
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct PciDevice {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class: u8,
    pub subclass: u8,
    pub prog_if: u8,
    pub header_type: u8,
    pub bar0: u32,
    pub bar1: u32,
    pub bar2: u32,
    pub bar3: u32,
    pub bar4: u32,
    pub bar5: u32,
    pub irq_line: u8,
    pub irq_pin: u8,
}

impl PciDevice {
    pub const fn empty() -> Self {
        Self {
            bus: 0,
            device: 0,
            function: 0,
            vendor_id: 0xFFFF,
            device_id: 0xFFFF,
            class: 0,
            subclass: 0,
            prog_if: 0,
            header_type: 0,
            bar0: 0,
            bar1: 0,
            bar2: 0,
            bar3: 0,
            bar4: 0,
            bar5: 0,
            irq_line: 0,
            irq_pin: 0,
        }
    }

    pub fn is_valid(&self) -> bool {
        self.vendor_id != 0xFFFF
    }
}

/// Static array of discovered devices
static mut DEVICES: [PciDevice; MAX_DEVICES] = [PciDevice::empty(); MAX_DEVICES];

/// Build a PCI configuration address
fn pci_address(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    // Enable bit + Bus + Device + Function + Offset
    (1u32 << 31)
        | ((bus as u32) << 16)
        | ((device as u32) << 11)
        | ((function as u32) << 8)
        | ((offset as u32) & 0xFC)
}

/// Read 32-bit value from PCI configuration space
pub fn pci_read32(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    let address = pci_address(bus, device, function, offset);
    unsafe {
        outl(PCI_CONFIG_ADDRESS, address);
        inl(PCI_CONFIG_DATA)
    }
}

/// Read 16-bit value from PCI configuration space
pub fn pci_read16(bus: u8, device: u8, function: u8, offset: u8) -> u16 {
    let value = pci_read32(bus, device, function, offset & 0xFC);
    ((value >> ((offset & 2) * 8)) & 0xFFFF) as u16
}

/// Read 8-bit value from PCI configuration space
pub fn pci_read8(bus: u8, device: u8, function: u8, offset: u8) -> u8 {
    let value = pci_read32(bus, device, function, offset & 0xFC);
    ((value >> ((offset & 3) * 8)) & 0xFF) as u8
}

/// Write 32-bit value to PCI configuration space
pub fn pci_write32(bus: u8, device: u8, function: u8, offset: u8, value: u32) {
    let address = pci_address(bus, device, function, offset);
    unsafe {
        outl(PCI_CONFIG_ADDRESS, address);
        outl(PCI_CONFIG_DATA, value);
    }
}

/// Write 16-bit value to PCI configuration space
pub fn pci_write16(bus: u8, device: u8, function: u8, offset: u8, value: u16) {
    let old = pci_read32(bus, device, function, offset & 0xFC);
    let shift = (offset & 2) * 8;
    let mask = !(0xFFFFu32 << shift);
    let new_value = (old & mask) | ((value as u32) << shift);
    pci_write32(bus, device, function, offset & 0xFC, new_value);
}

/// Write 8-bit value to PCI configuration space
pub fn pci_write8(bus: u8, device: u8, function: u8, offset: u8, value: u8) {
    let old = pci_read32(bus, device, function, offset & 0xFC);
    let shift = (offset & 3) * 8;
    let mask = !(0xFFu32 << shift);
    let new_value = (old & mask) | ((value as u32) << shift);
    pci_write32(bus, device, function, offset & 0xFC, new_value);
}

/// Check if a device exists at bus:device:function
fn device_exists(bus: u8, device: u8, function: u8) -> bool {
    pci_read16(bus, device, function, 0x00) != 0xFFFF
}

/// Read device information from PCI configuration space
fn read_device(bus: u8, device: u8, function: u8) -> PciDevice {
    let vendor_id = pci_read16(bus, device, function, 0x00);
    let device_id = pci_read16(bus, device, function, 0x02);
    let class = pci_read8(bus, device, function, 0x0B);
    let subclass = pci_read8(bus, device, function, 0x0A);
    let prog_if = pci_read8(bus, device, function, 0x09);
    let header_type = pci_read8(bus, device, function, 0x0E);

    let bar0 = pci_read32(bus, device, function, 0x10);
    let bar1 = pci_read32(bus, device, function, 0x14);
    let bar2 = pci_read32(bus, device, function, 0x18);
    let bar3 = pci_read32(bus, device, function, 0x1C);
    let bar4 = pci_read32(bus, device, function, 0x20);
    let bar5 = pci_read32(bus, device, function, 0x24);

    let irq_line = pci_read8(bus, device, function, 0x3C);
    let irq_pin = pci_read8(bus, device, function, 0x3D);

    PciDevice {
        bus,
        device,
        function,
        vendor_id,
        device_id,
        class,
        subclass,
        prog_if,
        header_type,
        bar0,
        bar1,
        bar2,
        bar3,
        bar4,
        bar5,
        irq_line,
        irq_pin,
    }
}

/// Initialize PCI subsystem and enumerate all devices
pub fn init() {
    if PCI_INIT.load(Ordering::Relaxed) {
        return;
    }

    serial::println(b"[PCI] Enumerating PCI devices...");

    let mut count: u32 = 0;

    // Scan all buses (0-255), devices (0-31), functions (0-7)
    for bus in 0..=255u8 {
        for device in 0..32u8 {
            // First check function 0
            if device_exists(bus, device, 0) {
                let dev = read_device(bus, device, 0);

                if count < MAX_DEVICES as u32 {
                    unsafe { DEVICES[count as usize] = dev; }
                    count += 1;
                }

                // Check if multi-function device
                if dev.header_type & 0x80 != 0 {
                    for function in 1..8u8 {
                        if device_exists(bus, device, function) {
                            let dev = read_device(bus, device, function);
                            if count < MAX_DEVICES as u32 {
                                unsafe { DEVICES[count as usize] = dev; }
                                count += 1;
                            }
                        }
                    }
                }
            }
        }
    }

    DEVICE_COUNT.store(count, Ordering::SeqCst);
    PCI_INIT.store(true, Ordering::SeqCst);

    serial::print(b"[PCI] Found ");
    serial::print_dec(count as u64);
    serial::println(b" devices");

    // Log notable devices
    for i in 0..count as usize {
        let dev = unsafe { DEVICES[i] };
        if dev.is_valid() {
            let class_name = match (dev.class, dev.subclass, dev.prog_if) {
                (0x0C, 0x03, 0x30) => "xHCI USB 3.0",
                (0x0C, 0x03, 0x20) => "EHCI USB 2.0",
                (0x0C, 0x03, 0x10) => "OHCI USB 1.1",
                (0x0C, 0x03, 0x00) => "UHCI USB 1.0",
                (0x01, 0x06, _) => "SATA AHCI",
                (0x01, 0x08, _) => "NVMe",
                (0x02, 0x00, _) => "Ethernet",
                (0x03, 0x00, _) => "VGA Controller",
                (0x06, 0x00, _) => "Host Bridge",
                (0x06, 0x01, _) => "ISA Bridge",
                (0x06, 0x04, _) => "PCI-PCI Bridge",
                _ => "",
            };

            if !class_name.is_empty() {
                serial::print(b"[PCI] ");
                serial::print_dec(dev.bus as u64);
                serial::print(b":");
                serial::print_dec(dev.device as u64);
                serial::print(b".");
                serial::print_dec(dev.function as u64);
                serial::print(b" ");
                serial::print(class_name.as_bytes());
                serial::print(b" (");
                serial::print_hex(dev.vendor_id as u64);
                serial::print(b":");
                serial::print_hex(dev.device_id as u64);
                serial::println(b")");
            }
        }
    }
}

/// Find a device by class/subclass/prog_if
pub fn find_device(class: u8, subclass: u8, prog_if: Option<u8>) -> Option<PciDevice> {
    let count = DEVICE_COUNT.load(Ordering::Relaxed) as usize;
    for i in 0..count {
        let dev = unsafe { DEVICES[i] };
        if dev.class == class && dev.subclass == subclass {
            if let Some(pi) = prog_if {
                if dev.prog_if == pi {
                    return Some(dev);
                }
            } else {
                return Some(dev);
            }
        }
    }
    None
}

/// Find all devices by class/subclass
pub fn find_devices(class: u8, subclass: u8) -> impl Iterator<Item = PciDevice> {
    let count = DEVICE_COUNT.load(Ordering::Relaxed) as usize;
    (0..count)
        .filter_map(move |i| {
            let dev = unsafe { DEVICES[i] };
            if dev.class == class && dev.subclass == subclass {
                Some(dev)
            } else {
                None
            }
        })
}

/// Get a device by index
pub fn get_device(index: usize) -> Option<PciDevice> {
    let count = DEVICE_COUNT.load(Ordering::Relaxed) as usize;
    if index < count {
        Some(unsafe { DEVICES[index] })
    } else {
        None
    }
}

/// Get total device count
pub fn device_count() -> usize {
    DEVICE_COUNT.load(Ordering::Relaxed) as usize
}

/// Check if PCI is initialized
pub fn is_init() -> bool {
    PCI_INIT.load(Ordering::Relaxed)
}

/// Enable bus mastering for a device (needed for DMA)
pub fn enable_bus_master(bus: u8, device: u8, function: u8) {
    let cmd = pci_read16(bus, device, function, 0x04);
    pci_write16(bus, device, function, 0x04, cmd | 0x04); // Set Bus Master bit
}

/// Enable memory space access for a device
pub fn enable_memory_space(bus: u8, device: u8, function: u8) {
    let cmd = pci_read16(bus, device, function, 0x04);
    pci_write16(bus, device, function, 0x04, cmd | 0x02); // Set Memory Space bit
}

/// Enable I/O space access for a device
pub fn enable_io_space(bus: u8, device: u8, function: u8) {
    let cmd = pci_read16(bus, device, function, 0x04);
    pci_write16(bus, device, function, 0x04, cmd | 0x01); // Set I/O Space bit
}

/// Get BAR address (handles both memory and I/O BARs)
pub fn get_bar_address(bar: u32) -> Option<u64> {
    if bar == 0 {
        return None;
    }

    // Check if I/O or Memory BAR
    if bar & 0x01 != 0 {
        // I/O BAR - address is bits 2-31
        Some((bar & 0xFFFF_FFFC) as u64)
    } else {
        // Memory BAR
        let bar_type = (bar >> 1) & 0x03;
        match bar_type {
            0x00 => {
                // 32-bit memory BAR
                Some((bar & 0xFFFF_FFF0) as u64)
            }
            0x02 => {
                // 64-bit memory BAR - need to read next BAR too
                // For now, just return lower 32 bits
                Some((bar & 0xFFFF_FFF0) as u64)
            }
            _ => None,
        }
    }
}
