//! PCI/PCIe Bus Manager

use core::fmt;
use alloc::vec::Vec;
use x86_64::PhysAddr;
use spin::Mutex;

// I/O ports for legacy PCI config mechanism #1
const PCI_CONFIG_ADDRESS: u16 = 0xCF8;
const PCI_CONFIG_DATA: u16 = 0xCFC;

#[inline(always)]
unsafe fn outl(port: u16, val: u32) {
    core::arch::asm!("out dx, eax", in("dx") port, in("eax") val);
}
#[inline(always)]
unsafe fn inl(port: u16) -> u32 {
    let mut val: u32;
    core::arch::asm!("in eax, dx", in("dx") port, out("eax") val);
    val
}

#[inline(always)]
fn pci_config_addr(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    (1u32 << 31)
        | ((bus as u32) << 16)
        | ((device as u32) << 11)
        | ((function as u32) << 8)
        | ((offset as u32) & 0xFC)
}

#[inline(always)]
pub fn pci_read_config32(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    unsafe {
        outl(PCI_CONFIG_ADDRESS, pci_config_addr(bus, device, function, offset));
        inl(PCI_CONFIG_DATA)
    }
}

#[inline(always)]
pub fn pci_write_config32(bus: u8, device: u8, function: u8, offset: u8, value: u32) {
    unsafe {
        outl(PCI_CONFIG_ADDRESS, pci_config_addr(bus, device, function, offset));
        outl(PCI_CONFIG_DATA, value);
    }
}

#[derive(Clone, Copy, Debug)]
pub enum PciBar {
    Memory { address: PhysAddr, size: usize, is_prefetchable: bool, is_64bit: bool },
    Io { port: u16, size: usize },
}

#[derive(Clone, Copy, Debug)]
pub struct PciCapability {
    pub id: u8,
    pub offset: u8, // config-space offset of this capability
}

#[derive(Clone, Debug)]
pub struct PciDevice {
    pub bus: u8,
    pub device: u8,
    pub function: u8,
    pub vendor_id: u16,
    pub device_id: u16,
    pub class: u8,
    pub subclass: u8,
    pub progif: u8,
    pub revision: u8,
    pub bars: [Option<PciBar>; 6],
    pub capabilities: Vec<PciCapability>,
}

impl PciDevice {
    pub fn get_bar(&self, index: usize) -> Result<PciBar, &'static str> {
        self.bars.get(index).and_then(|b| *b).ok_or("BAR not present")
    }

    /// Configure MSI (single vector)
    pub fn configure_msi(&mut self, vector: u8) -> Result<(), &'static str> {
        if let Some(msi_cap) = self.capabilities.iter().find(|c| c.id == 0x05) {
            let off = msi_cap.offset;
            let msg_ctrl = (pci_read_config32(self.bus, self.device, self.function, off + 2) >> 16) as u16;
            let is_64 = (msg_ctrl & (1 << 7)) != 0;
            // Write Message Address (APIC). Typically 0xFEE0_0000 | (dest_id << 12)
            let msg_addr = 0xFEE0_0000u32;
            pci_write_config32(self.bus, self.device, self.function, off + 4, msg_addr);
            let mut woff = off + 8;
            if is_64 {
                // Upper 32 bits (usually zero)
                pci_write_config32(self.bus, self.device, self.function, off + 8, 0);
                woff = off + 12;
            }
            // Message Data: vector in low bits, delivery mode=Fixed (0), level=0, trigger=Edge
            let msg_data = vector as u32;
            pci_write_config32(self.bus, self.device, self.function, woff, msg_data);

            // Enable MSI
            let mut msg_ctrl2 = pci_read_config32(self.bus, self.device, self.function, off + 2);
            msg_ctrl2 |= 1 << 16; // MSI Enable
            pci_write_config32(self.bus, self.device, self.function, off + 2, msg_ctrl2);
            Ok(())
        } else {
            Err("MSI capability not present")
        }
    }

    /// Configure MSI-X (single vector, table entry 0)
    pub fn configure_msix(&mut self, vector: u8) -> Result<(), &'static str> {
        let msix_cap = self.capabilities.iter().find(|c| c.id == 0x11).ok_or("MSI-X capability not present")?;
        let off = msix_cap.offset;

        let msg_ctrl = pci_read_config32(self.bus, self.device, self.function, off + 2);
        let table = pci_read_config32(self.bus, self.device, self.function, off + 4);
        let pba = pci_read_config32(self.bus, self.device, self.function, off + 8);

        let table_bar_index = (table & 0x7) as usize;
        let table_offset = table & !0x7;
        let _pba_bar_index = (pba & 0x7) as usize;
        // let pba_offset = pba & !0x7;

        let bar = self.get_bar(table_bar_index)?;
        let table_phys = match bar {
            PciBar::Memory { address, .. } => address.as_u64().wrapping_add(table_offset as u64),
            _ => return Err("MSI-X table is not in MMIO"),
        };

        // Map the table entry 0 (16 bytes): msg_addr (8), msg_data (4), vector_ctrl (4)
        // Here we assume identity mapping or ioremap done elsewhere; we use mmio helpers.
        let entry0 = table_phys as usize;

        // Program message address to local APIC, data=vector, unmask
        let msg_addr_lo = 0xFEE0_0000u32;
        let msg_addr_hi = 0u32;
        let msg_data = vector as u32;
        let vector_ctrl_mask = 0u32; // unmasked

        unsafe {
            crate::memory::mmio::mmio_w32(entry0 + 0, msg_addr_lo);
            crate::memory::mmio::mmio_w32(entry0 + 4, msg_addr_hi);
            crate::memory::mmio::mmio_w32(entry0 + 8, msg_data);
            crate::memory::mmio::mmio_w32(entry0 + 12, vector_ctrl_mask);
        }

        // Enable MSI-X in capability
        let mut ctrl = msg_ctrl | (1 << 31); // MSI-X Enable
        // Optionally mask all -> here we do not set Function Mask
        pci_write_config32(self.bus, self.device, self.function, off + 2, ctrl);

        Ok(())
    }
}

impl fmt::Display for PciDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02x}:{:02x}.{} {:04x}:{:04x} class {:02x}.{:02x}.{:02x}",
            self.bus, self.device, self.function,
            self.vendor_id, self.device_id,
            self.class, self.subclass, self.progif)
    }
}

fn decode_bar(bus: u8, dev: u8, fun: u8, index: u8) -> Option<PciBar> {
    let off = 0x10 + (index as u8 * 4);
    let original = pci_read_config32(bus, dev, fun, off);
    if original == 0 || original == 0xFFFF_FFFF { return None; }

    // Write all 1s to determine size mask
    pci_write_config32(bus, dev, fun, off, 0xFFFF_FFFF);
    let size_mask = pci_read_config32(bus, dev, fun, off);
    // Restore
    pci_write_config32(bus, dev, fun, off, original);

    if (original & 1) == 1 {
        // I/O BAR
        let port = (original & 0xFFFC) as u16;
        let size = (!((size_mask & 0xFFFC) as u32) + 1) as usize;
        Some(PciBar::Io { port, size })
    } else {
        // Memory BAR
        let is_prefetch = (original & (1 << 3)) != 0;
        let type_bits = (original >> 1) & 0x3;
        let mut addr64 = (original & 0xFFFF_FFF0) as u64;
        let is_64bit = type_bits == 0x2;

        let size_low = size_mask & 0xFFFF_FFF0;
        let mut size64 = size_low as u64;

        if is_64bit {
            // Read high dword
            let original_hi = pci_read_config32(bus, dev, fun, off + 4);
            // Probe size high
            pci_write_config32(bus, dev, fun, off + 4, 0xFFFF_FFFF);
            let size_mask_hi = pci_read_config32(bus, dev, fun, off + 4);
            // Restore
            pci_write_config32(bus, dev, fun, off + 4, original_hi);

            addr64 |= (original_hi as u64) << 32;
            size64 |= (size_mask_hi as u64) << 32;
        }

        let size = (!size64 + 1) as usize;
        Some(PciBar::Memory {
            address: PhysAddr::new(addr64),
            size,
            is_prefetchable: is_prefetch,
            is_64bit,
        })
    }
}

fn read_capabilities(bus: u8, dev: u8, fun: u8) -> Vec<PciCapability> {
    let mut caps = Vec::new();

    // Check status bit for capabilities list
    let status = ((pci_read_config32(bus, dev, fun, 0x04) >> 16) & 0xFFFF) as u16;
    if (status & (1 << 4)) == 0 {
        return caps;
    }

    // Capabilities Pointer at 0x34 (byte pointer)
    let mut ptr = (pci_read_config32(bus, dev, fun, 0x34) & 0xFF) as u8;
    let mut guard = 0;
    while ptr != 0 && ptr >= 0x40 && guard < 64 {
        let header = pci_read_config32(bus, dev, fun, ptr);
        let id = (header & 0xFF) as u8;
        let next = ((header >> 8) & 0xFF) as u8;
        caps.push(PciCapability { id, offset: ptr });
        ptr = next;
        guard += 1;
    }

    caps
}

fn probe_function(bus: u8, device: u8, function: u8, out: &mut Vec<PciDevice>) {
    let id = pci_read_config32(bus, device, function, 0x00);
    let vendor_id = (id & 0xFFFF) as u16;
    if vendor_id == 0xFFFF { return; }

    let device_id = ((id >> 16) & 0xFFFF) as u16;

    let class_reg = pci_read_config32(bus, device, function, 0x08);
    let class = ((class_reg >> 24) & 0xFF) as u8;
    let subclass = ((class_reg >> 16) & 0xFF) as u8;
    let progif = ((class_reg >> 8) & 0xFF) as u8;
    let revision = (class_reg & 0xFF) as u8;

    // BARs
    let mut bars: [Option<PciBar>; 6] = [None, None, None, None, None, None];
    let mut bar_index = 0;
    while bar_index < 6 {
        if let Some(bar) = decode_bar(bus, device, function, bar_index as u8) {
            let is_64 = matches!(bar, PciBar::Memory { is_64bit: true, .. });
            bars[bar_index] = Some(bar);
            bar_index += if is_64 { 2 } else { 1 };
        } else {
            bar_index += 1;
        }
    }

    // Capabilities
    let capabilities = read_capabilities(bus, device, function);

    out.push(PciDevice {
        bus, device, function,
        vendor_id, device_id,
        class, subclass, progif, revision,
        bars, capabilities,
    });
}

pub fn scan_and_collect() -> Vec<PciDevice> {
    let mut devs = Vec::new();
    for bus in 0u8..=255 {
        for device in 0u8..32 {
            let id = pci_read_config32(bus, device, 0, 0x00);
            if (id & 0xFFFF) as u16 == 0xFFFF { continue; }

            // Multi-function?
            let hdr = pci_read_config32(bus, device, 0, 0x0C);
            let multi = ((hdr >> 16) & 0x80) != 0;

            probe_function(bus, device, 0, &mut devs);
            if multi {
                for function in 1u8..8u8 {
                    probe_function(bus, device, function, &mut devs);
                }
            }
        }
    }
    devs
}

pub fn find_device_by_class(class: u8, subclass: u8) -> Option<PciDevice> {
    scan_and_collect()
        .into_iter()
        .find(|d| d.class == class && d.subclass == subclass)
}

pub fn find_device_by_id(vendor_id: u16, device_id: u16) -> Option<PciDevice> {
    scan_and_collect()
        .into_iter()
        .find(|d| d.vendor_id == vendor_id && d.device_id == device_id)
}

// Simple manager wrapper for reuse

pub struct PciManager {
    devices: Vec<PciDevice>,
}

static PCI_MANAGER: Mutex<Option<PciManager>> = Mutex::new(None);

pub fn init_pci() -> Result<(), &'static str> {
    let devs = scan_and_collect();
    *PCI_MANAGER.lock() = Some(PciManager { devices: devs });
    Ok(())
}

pub fn get_pci_manager() -> Option<&'static PciManager> {
    // Leak a static reference for simplicity
    let mut guard = PCI_MANAGER.lock();
    if guard.is_none() {
        return None;
    }
    let r = guard.as_ref().unwrap() as *const PciManager;
    // Safety: stays leaked during kernel lifetime
    Some(unsafe { &*r })
}

impl PciManager {
    pub fn enumerate_all_devices(&self) -> Vec<PciDevice> {
        self.devices.clone()
    }
}
