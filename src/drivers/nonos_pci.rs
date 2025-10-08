//! Advanced PCI Device Management
//!
//! Enterprise PCI/PCIe subsystem with DMA and MSI-X support

use alloc::{vec::Vec, vec, string::String, collections::BTreeMap};
use core::sync::atomic::{AtomicU32, AtomicU64, AtomicBool, Ordering};
use spin::{Mutex, RwLock};
use x86_64::{VirtAddr, PhysAddr, instructions::port::{PortReadOnly, PortWriteOnly}};

/// PCI configuration space offsets
const PCI_CONFIG_VENDOR_ID: u8 = 0x00;
const PCI_CONFIG_DEVICE_ID: u8 = 0x02;
const PCI_CONFIG_COMMAND: u8 = 0x04;
const PCI_CONFIG_STATUS: u8 = 0x06;
const PCI_CONFIG_REVISION_ID: u8 = 0x08;
const PCI_CONFIG_PROG_IF: u8 = 0x09;
const PCI_CONFIG_SUBCLASS: u8 = 0x0A;
const PCI_CONFIG_CLASS_CODE: u8 = 0x0B;
const PCI_CONFIG_HEADER_TYPE: u8 = 0x0E;
const PCI_CONFIG_BAR0: u8 = 0x10;
const PCI_CONFIG_BAR1: u8 = 0x14;
const PCI_CONFIG_BAR2: u8 = 0x18;
const PCI_CONFIG_BAR3: u8 = 0x1C;
const PCI_CONFIG_BAR4: u8 = 0x20;
const PCI_CONFIG_BAR5: u8 = 0x24;
const PCI_CONFIG_SUBSYSTEM_VENDOR_ID: u8 = 0x2C;
const PCI_CONFIG_SUBSYSTEM_ID: u8 = 0x2E;
const PCI_CONFIG_CAPABILITIES_PTR: u8 = 0x34;
const PCI_CONFIG_INTERRUPT_LINE: u8 = 0x3C;
const PCI_CONFIG_INTERRUPT_PIN: u8 = 0x3D;

/// PCI command register bits
const PCI_COMMAND_IO: u16 = 0x01;
const PCI_COMMAND_MEMORY: u16 = 0x02;
const PCI_COMMAND_MASTER: u16 = 0x04;
const PCI_COMMAND_SPECIAL: u16 = 0x08;
const PCI_COMMAND_INVALIDATE: u16 = 0x10;
const PCI_COMMAND_VGA_PALETTE: u16 = 0x20;
const PCI_COMMAND_PARITY: u16 = 0x40;
const PCI_COMMAND_WAIT: u16 = 0x80;
const PCI_COMMAND_SERR: u16 = 0x100;
const PCI_COMMAND_FAST_BACK: u16 = 0x200;
const PCI_COMMAND_INTX_DISABLE: u16 = 0x400;

/// PCI capability IDs
const PCI_CAP_ID_PM: u8 = 0x01;     // Power Management
const PCI_CAP_ID_AGP: u8 = 0x02;    // AGP
const PCI_CAP_ID_VPD: u8 = 0x03;    // Vital Product Data
const PCI_CAP_ID_SLOTID: u8 = 0x04; // Slot Identification
const PCI_CAP_ID_MSI: u8 = 0x05;    // Message Signalled Interrupts
const PCI_CAP_ID_CHSWP: u8 = 0x06;  // CompactPCI HotSwap
const PCI_CAP_ID_PCIX: u8 = 0x07;   // PCI-X
const PCI_CAP_ID_HT: u8 = 0x08;     // HyperTransport
const PCI_CAP_ID_VNDR: u8 = 0x09;   // Vendor-Specific
const PCI_CAP_ID_DBG: u8 = 0x0A;    // Debug port
const PCI_CAP_ID_CCRC: u8 = 0x0B;   // CompactPCI Central Resource Control
const PCI_CAP_ID_SHPC: u8 = 0x0C;   // PCI Standard Hot-Plug Controller
const PCI_CAP_ID_SSVID: u8 = 0x0D;  // Bridge subsystem vendor/device ID
const PCI_CAP_ID_AGP3: u8 = 0x0E;   // AGP Target PCI-PCI bridge
const PCI_CAP_ID_SECDEV: u8 = 0x0F; // Secure Device
const PCI_CAP_ID_EXP: u8 = 0x10;    // PCI Express
const PCI_CAP_ID_MSIX: u8 = 0x11;   // MSI-X

/// MSI-X capability structure
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MsixCapability {
    pub cap_id: u8,
    pub next_ptr: u8,
    pub message_control: u16,
    pub table_offset: u32,
    pub pba_offset: u32,
}

/// MSI-X table entry
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MsixTableEntry {
    pub msg_addr_low: u32,
    pub msg_addr_high: u32,
    pub msg_data: u32,
    pub vector_control: u32,
}

/// DMA descriptor for scatter-gather operations
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DmaDescriptor {
    pub addr: u64,
    pub length: u32,
    pub flags: u32,
}

/// DMA engine state
#[derive(Debug)]
pub struct DmaEngine {
    pub channel_id: u32,
    pub base_addr: PhysAddr,
    pub ring_buffer: Vec<DmaDescriptor>,
    pub head: AtomicU32,
    pub tail: AtomicU32,
    pub active: AtomicBool,
    pub completed_transfers: AtomicU64,
    pub failed_transfers: AtomicU64,
}

impl DmaEngine {
    /// Create new DMA engine
    pub fn new(channel_id: u32, base_addr: PhysAddr, ring_size: usize) -> Self {
        DmaEngine {
            channel_id,
            base_addr,
            ring_buffer: vec![DmaDescriptor { addr: 0, length: 0, flags: 0 }; ring_size],
            head: AtomicU32::new(0),
            tail: AtomicU32::new(0),
            active: AtomicBool::new(false),
            completed_transfers: AtomicU64::new(0),
            failed_transfers: AtomicU64::new(0),
        }
    }
    
    /// Submit DMA transfer
    pub fn submit_transfer(&mut self, src_addr: PhysAddr, _dst_addr: PhysAddr, length: u32) -> Result<(), &'static str> {
        let tail = self.tail.load(Ordering::Relaxed);
        let next_tail = (tail + 1) % self.ring_buffer.len() as u32;
        let head = self.head.load(Ordering::Acquire);
        
        if next_tail == head {
            return Err("DMA ring buffer full");
        }
        
        // Create descriptor
        let descriptor = DmaDescriptor {
            addr: src_addr.as_u64(),
            length,
            flags: 0x01, // Transfer ready flag
        };
        
        self.ring_buffer[tail as usize] = descriptor;
        
        // Update tail pointer
        self.tail.store(next_tail, Ordering::Release);
        
        // Notify hardware (would write to device registers)
        self.notify_hardware();
        
        Ok(())
    }
    
    /// Start DMA engine
    pub fn start(&self) -> Result<(), &'static str> {
        self.active.store(true, Ordering::Relaxed);
        
        // Enable DMA engine in hardware
        unsafe {
            let control_reg = (self.base_addr.as_u64() + 0x08) as *mut u32;
            let current = core::ptr::read_volatile(control_reg);
            core::ptr::write_volatile(control_reg, current | 0x01); // Enable bit
        }
        
        Ok(())
    }
    
    /// Stop DMA engine
    pub fn stop(&self) -> Result<(), &'static str> {
        self.active.store(false, Ordering::Relaxed);
        
        // Disable DMA engine in hardware
        unsafe {
            let control_reg = (self.base_addr.as_u64() + 0x08) as *mut u32;
            let current = core::ptr::read_volatile(control_reg);
            core::ptr::write_volatile(control_reg, current & !0x01); // Clear enable bit
        }
        
        Ok(())
    }
    
    /// Process completed transfers
    pub fn process_completions(&mut self) -> usize {
        let mut completions = 0;
        let head = self.head.load(Ordering::Relaxed);
        let tail = self.tail.load(Ordering::Acquire);
        
        // Read hardware completion pointer
        let hw_head = unsafe {
            let head_reg = (self.base_addr.as_u64() + 0x04) as *const u32;
            core::ptr::read_volatile(head_reg)
        };
        
        while head != hw_head && head != tail {
            let descriptor = &self.ring_buffer[head as usize];
            
            // Check if transfer completed successfully
            if descriptor.flags & 0x80000000 != 0 {
                self.completed_transfers.fetch_add(1, Ordering::Relaxed);
            } else {
                self.failed_transfers.fetch_add(1, Ordering::Relaxed);
            }
            
            completions += 1;
            let new_head = (head + 1) % self.ring_buffer.len() as u32;
            self.head.store(new_head, Ordering::Release);
        }
        
        completions
    }
    
    /// Notify hardware of new descriptors
    fn notify_hardware(&self) {
        unsafe {
            let tail_reg = (self.base_addr.as_u64() + 0x00) as *mut u32;
            core::ptr::write_volatile(tail_reg, self.tail.load(Ordering::Relaxed));
        }
    }
}

/// PCI Base Address Register
#[derive(Debug, Clone, Copy)]
pub enum PciBar {
    Memory {
        address: PhysAddr,
        size: usize,
        prefetchable: bool,
        address_64bit: bool,
    },
    Io {
        port: u16,
        size: usize,
    },
}

/// PCI device capability
#[derive(Debug, Clone)]
pub struct PciCapability {
    pub id: u8,
    pub offset: u8,
    pub length: u8,
    pub data: Vec<u8>,
}

/// PCI device information
#[derive(Debug)]
pub struct PciDevice {
    pub bus: u8,
    pub device: u8,
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
    
    // BARs (Base Address Registers)
    pub bars: [Option<PciBar>; 6],
    
    // Capabilities
    pub capabilities: Vec<PciCapability>,
    
    // MSI-X support
    pub msix_capability: Option<MsixCapability>,
    pub msix_table: Option<Vec<MsixTableEntry>>,
    pub msix_enabled: AtomicBool,
    
    // DMA engines
    pub dma_engines: Vec<Mutex<DmaEngine>>,
    
    // Device-specific data
    pub driver_data: Option<VirtAddr>,
}

impl PciDevice {
    /// Create new PCI device
    pub fn new(bus: u8, device: u8, function: u8) -> Result<Self, &'static str> {
        let mut pci_dev = PciDevice {
            bus,
            device,
            function,
            vendor_id: 0,
            device_id: 0,
            class_code: 0,
            subclass: 0,
            prog_if: 0,
            revision_id: 0,
            header_type: 0,
            interrupt_line: 0,
            interrupt_pin: 0,
            bars: [None; 6],
            capabilities: Vec::new(),
            msix_capability: None,
            msix_table: None,
            msix_enabled: AtomicBool::new(false),
            dma_engines: Vec::new(),
            driver_data: None,
        };
        
        // Read basic device information
        pci_dev.read_config_info()?;
        
        // Parse BARs
        pci_dev.parse_bars()?;
        
        // Parse capabilities
        pci_dev.parse_capabilities()?;
        
        // Setup MSI-X if supported
        if pci_dev.msix_capability.is_some() {
            pci_dev.setup_msix()?;
        }
        
        Ok(pci_dev)
    }
    
    /// Read PCI configuration space
    pub fn read_config_u32(&self, offset: u8) -> u32 {
        let address = 0x80000000u32 |
                     ((self.bus as u32) << 16) |
                     ((self.device as u32) << 11) |
                     ((self.function as u32) << 8) |
                     (offset as u32 & 0xFC);
        
        unsafe {
            let mut config_address_port = PortWriteOnly::new(0xCF8);
            let mut config_data_port = PortReadOnly::new(0xCFC);
            
            config_address_port.write(address);
            config_data_port.read()
        }
    }
    
    /// Write PCI configuration space
    pub fn write_config_u32(&self, offset: u8, value: u32) {
        let address = 0x80000000u32 |
                     ((self.bus as u32) << 16) |
                     ((self.device as u32) << 11) |
                     ((self.function as u32) << 8) |
                     (offset as u32 & 0xFC);
        
        unsafe {
            let mut config_address_port = PortWriteOnly::new(0xCF8);
            let mut config_data_port = PortWriteOnly::new(0xCFC);
            
            config_address_port.write(address);
            config_data_port.write(value);
        }
    }
    
    /// Read 16-bit value from config space
    pub fn read_config_u16(&self, offset: u8) -> u16 {
        let dword = self.read_config_u32(offset & 0xFC);
        let shift = ((offset & 0x03) * 8) as u32;
        ((dword >> shift) & 0xFFFF) as u16
    }
    
    /// Write 16-bit value to config space
    pub fn write_config_u16(&self, offset: u8, value: u16) {
        let dword_offset = offset & 0xFC;
        let shift = ((offset & 0x03) * 8) as u32;
        let mask = !(0xFFFFu32 << shift);
        
        let current = self.read_config_u32(dword_offset);
        let new_value = (current & mask) | ((value as u32) << shift);
        
        self.write_config_u32(dword_offset, new_value);
    }
    
    /// Read basic device configuration
    fn read_config_info(&mut self) -> Result<(), &'static str> {
        self.vendor_id = self.read_config_u16(PCI_CONFIG_VENDOR_ID);
        
        if self.vendor_id == 0xFFFF {
            return Err("Invalid vendor ID");
        }
        
        self.device_id = self.read_config_u16(PCI_CONFIG_DEVICE_ID);
        self.class_code = (self.read_config_u32(PCI_CONFIG_CLASS_CODE) >> 24) as u8;
        self.subclass = ((self.read_config_u32(PCI_CONFIG_SUBCLASS) >> 16) & 0xFF) as u8;
        self.prog_if = ((self.read_config_u32(PCI_CONFIG_PROG_IF) >> 8) & 0xFF) as u8;
        self.revision_id = (self.read_config_u32(PCI_CONFIG_REVISION_ID) & 0xFF) as u8;
        self.header_type = (self.read_config_u32(PCI_CONFIG_HEADER_TYPE) >> 16 & 0xFF) as u8;
        self.interrupt_line = (self.read_config_u32(PCI_CONFIG_INTERRUPT_LINE) & 0xFF) as u8;
        self.interrupt_pin = ((self.read_config_u32(PCI_CONFIG_INTERRUPT_PIN) >> 8) & 0xFF) as u8;
        
        Ok(())
    }
    
    /// Parse Base Address Registers
    fn parse_bars(&mut self) -> Result<(), &'static str> {
        let mut i = 0;
        while i < 6 {
            let bar_offset = PCI_CONFIG_BAR0 + (i as u8 * 4);
            let bar_value = self.read_config_u32(bar_offset);
            
            if bar_value == 0 {
                i += 1;
                continue;
            }
            
            if bar_value & 0x01 != 0 {
                // I/O BAR
                let port = (bar_value & 0xFFFC) as u16;
                
                // Write 0xFFFFFFFF to get size
                self.write_config_u32(bar_offset, 0xFFFFFFFF);
                let size_mask = self.read_config_u32(bar_offset);
                self.write_config_u32(bar_offset, bar_value); // Restore
                
                let size = (!(size_mask & 0xFFFC) + 1) as usize;
                
                self.bars[i] = Some(PciBar::Io { port, size });
                i += 1;
            } else {
                // Memory BAR
                let prefetchable = (bar_value & 0x08) != 0;
                let address_64bit = ((bar_value >> 1) & 0x03) == 0x02;
                
                let mut address = (bar_value & 0xFFFFFFF0) as u64;
                let mut bar_count = 1;
                
                if address_64bit && i < 5 {
                    let high_bar = self.read_config_u32(bar_offset + 4);
                    address |= (high_bar as u64) << 32;
                    bar_count = 2;
                }
                
                // Get size
                self.write_config_u32(bar_offset, 0xFFFFFFFF);
                let size_mask = self.read_config_u32(bar_offset) as u64;
                
                let mut full_size_mask = size_mask;
                if address_64bit && i < 5 {
                    self.write_config_u32(bar_offset + 4, 0xFFFFFFFF);
                    let high_size_mask = self.read_config_u32(bar_offset + 4) as u64;
                    full_size_mask |= high_size_mask << 32;
                }
                
                let size = (!(full_size_mask & 0xFFFFFFFFFFFFFFF0) + 1) as usize;
                
                // Restore original values
                self.write_config_u32(bar_offset, bar_value);
                if address_64bit && i < 5 {
                    let high_bar = self.read_config_u32(bar_offset + 4);
                    self.write_config_u32(bar_offset + 4, high_bar);
                }
                
                self.bars[i] = Some(PciBar::Memory {
                    address: PhysAddr::new(address),
                    size,
                    prefetchable,
                    address_64bit,
                });
                
                // Skip next BAR if 64-bit
                if address_64bit {
                    i += 2; // Skip this BAR and the next one
                } else {
                    i += 1;
                }
            }
        }
        
        Ok(())
    }
    
    /// Parse PCI capabilities
    fn parse_capabilities(&mut self) -> Result<(), &'static str> {
        let status = self.read_config_u16(PCI_CONFIG_STATUS);
        
        // Check if capabilities are supported
        if status & 0x10 == 0 {
            return Ok(());
        }
        
        let mut cap_ptr = (self.read_config_u32(PCI_CONFIG_CAPABILITIES_PTR) & 0xFF) as u8;
        
        while cap_ptr != 0 && cap_ptr != 0xFF {
            let cap_header = self.read_config_u32(cap_ptr);
            let cap_id = (cap_header & 0xFF) as u8;
            let next_ptr = ((cap_header >> 8) & 0xFF) as u8;
            
            // Determine capability length based on ID
            let cap_length = match cap_id {
                PCI_CAP_ID_PM => 8,
                PCI_CAP_ID_MSI => {
                    let msg_ctrl = self.read_config_u16(cap_ptr + 2);
                    if msg_ctrl & 0x80 != 0 { 24 } else { 14 } // 64-bit vs 32-bit
                },
                PCI_CAP_ID_MSIX => 12,
                PCI_CAP_ID_EXP => {
                    let cap_reg = self.read_config_u16(cap_ptr + 2);
                    let version = (cap_reg >> 12) & 0x0F;
                    if version >= 2 { 60 } else { 20 }
                },
                _ => 8, // Default size
            };
            
            // Read capability data
            let mut cap_data = Vec::with_capacity(cap_length);
            for i in 0..cap_length {
                if i % 4 == 0 {
                    let dword = self.read_config_u32(cap_ptr + i as u8);
                    cap_data.push((dword & 0xFF) as u8);
                    if i + 1 < cap_length { cap_data.push(((dword >> 8) & 0xFF) as u8); }
                    if i + 2 < cap_length { cap_data.push(((dword >> 16) & 0xFF) as u8); }
                    if i + 3 < cap_length { cap_data.push(((dword >> 24) & 0xFF) as u8); }
                }
            }
            
            let capability = PciCapability {
                id: cap_id,
                offset: cap_ptr,
                length: cap_length as u8,
                data: cap_data,
            };
            
            // Handle specific capabilities
            match cap_id {
                PCI_CAP_ID_MSIX => {
                    self.parse_msix_capability(&capability)?;
                },
                _ => {}
            }
            
            self.capabilities.push(capability);
            cap_ptr = next_ptr;
        }
        
        Ok(())
    }
    
    /// Parse MSI-X capability
    fn parse_msix_capability(&mut self, capability: &PciCapability) -> Result<(), &'static str> {
        if capability.data.len() < 12 {
            return Err("Invalid MSI-X capability size");
        }
        
        let message_control = u16::from_le_bytes([capability.data[2], capability.data[3]]);
        let table_offset = u32::from_le_bytes([
            capability.data[4], capability.data[5],
            capability.data[6], capability.data[7]
        ]);
        let pba_offset = u32::from_le_bytes([
            capability.data[8], capability.data[9],
            capability.data[10], capability.data[11]
        ]);
        
        self.msix_capability = Some(MsixCapability {
            cap_id: capability.id,
            next_ptr: 0,
            message_control,
            table_offset,
            pba_offset,
        });
        
        Ok(())
    }
    
    /// Setup MSI-X interrupts
    fn setup_msix(&mut self) -> Result<(), &'static str> {
        let msix_cap = self.msix_capability.ok_or("No MSI-X capability")?;
        
        let table_size = (msix_cap.message_control & 0x7FF) as usize + 1;
        let table_bir = (msix_cap.table_offset & 0x07) as usize;
        let table_offset = (msix_cap.table_offset & !0x07) as usize;
        
        // Get table BAR
        let table_bar = self.bars[table_bir].ok_or("Invalid MSI-X table BAR")?;
        
        let table_addr = match table_bar {
            PciBar::Memory { address, .. } => address + table_offset,
            _ => return Err("MSI-X table BAR must be memory"),
        };
        
        // Initialize MSI-X table
        let mut msix_table = Vec::with_capacity(table_size);
        for i in 0..table_size {
            let entry_addr = table_addr + (i * 16); // Each entry is 16 bytes
            
            unsafe {
                let entry_ptr = entry_addr.as_u64() as *mut MsixTableEntry;
                let entry = MsixTableEntry {
                    msg_addr_low: 0,
                    msg_addr_high: 0,
                    msg_data: 0,
                    vector_control: 1, // Masked initially
                };
                core::ptr::write(entry_ptr, entry);
                msix_table.push(entry);
            }
        }
        
        self.msix_table = Some(msix_table);
        Ok(())
    }
    
    /// Enable MSI-X interrupts
    pub fn enable_msix(&self) -> Result<(), &'static str> {
        let msix_cap = self.msix_capability.ok_or("No MSI-X capability")?;
        
        // Enable MSI-X in capability
        let mut message_control = self.read_config_u16(msix_cap.cap_id + 2);
        message_control |= 0x8000; // Enable bit
        message_control &= !0x4000; // Clear mask bit
        
        self.write_config_u16(msix_cap.cap_id + 2, message_control);
        
        // Disable INTx interrupts
        let mut command = self.read_config_u16(PCI_CONFIG_COMMAND);
        command |= PCI_COMMAND_INTX_DISABLE;
        self.write_config_u16(PCI_CONFIG_COMMAND, command);
        
        self.msix_enabled.store(true, Ordering::Relaxed);
        Ok(())
    }
    
    /// Configure MSI-X vector
    pub fn configure_msix_vector(&self, vector: usize, msg_addr: u64, msg_data: u32) -> Result<(), &'static str> {
        let msix_table = self.msix_table.as_ref().ok_or("MSI-X not initialized")?;
        
        if vector >= msix_table.len() {
            return Err("Invalid MSI-X vector");
        }
        
        let msix_cap = self.msix_capability.ok_or("No MSI-X capability")?;
        let table_bir = (msix_cap.table_offset & 0x07) as usize;
        let table_offset = (msix_cap.table_offset & !0x07) as usize;
        
        let table_bar = self.bars[table_bir].ok_or("Invalid MSI-X table BAR")?;
        let table_addr = match table_bar {
            PciBar::Memory { address, .. } => address + table_offset,
            _ => return Err("MSI-X table BAR must be memory"),
        };
        
        let entry_addr = table_addr + (vector * 16);
        
        unsafe {
            let entry_ptr = entry_addr.as_u64() as *mut MsixTableEntry;
            let mut entry = core::ptr::read(entry_ptr);
            
            entry.msg_addr_low = (msg_addr & 0xFFFFFFFF) as u32;
            entry.msg_addr_high = (msg_addr >> 32) as u32;
            entry.msg_data = msg_data;
            entry.vector_control &= !1; // Unmask vector
            
            core::ptr::write(entry_ptr, entry);
        }
        
        Ok(())
    }
    
    /// Add DMA engine
    pub fn add_dma_engine(&mut self, base_addr: PhysAddr, ring_size: usize) -> Result<u32, &'static str> {
        let channel_id = self.dma_engines.len() as u32;
        let dma_engine = DmaEngine::new(channel_id, base_addr, ring_size);
        
        self.dma_engines.push(Mutex::new(dma_engine));
        Ok(channel_id)
    }
    
    /// Get DMA engine
    pub fn get_dma_engine(&self, channel_id: u32) -> Option<&Mutex<DmaEngine>> {
        self.dma_engines.get(channel_id as usize)
    }
    
    /// Enable bus mastering
    pub fn enable_bus_mastering(&self) {
        let mut command = self.read_config_u16(PCI_CONFIG_COMMAND);
        command |= PCI_COMMAND_MASTER | PCI_COMMAND_MEMORY;
        self.write_config_u16(PCI_CONFIG_COMMAND, command);
    }
}

impl Clone for PciDevice {
    fn clone(&self) -> Self {
        PciDevice {
            bus: self.bus,
            device: self.device,
            function: self.function,
            vendor_id: self.vendor_id,
            device_id: self.device_id,
            class_code: self.class_code,
            subclass: self.subclass,
            prog_if: self.prog_if,
            revision_id: self.revision_id,
            header_type: self.header_type,
            interrupt_line: self.interrupt_line,
            interrupt_pin: self.interrupt_pin,
            bars: self.bars.clone(),
            capabilities: self.capabilities.clone(),
            msix_capability: self.msix_capability.clone(),
            msix_table: self.msix_table.clone(),
            msix_enabled: AtomicBool::new(self.msix_enabled.load(Ordering::Relaxed)),
            dma_engines: Vec::new(), // Start with empty DMA engines for clone
            driver_data: self.driver_data,
        }
    }
}

/// PCI device manager
pub struct PciManager {
    pub devices: RwLock<BTreeMap<(u8, u8, u8), PciDevice>>,
    pub device_drivers: RwLock<BTreeMap<(u16, u16), String>>, // (vendor_id, device_id) -> driver
}

impl PciManager {
    /// Create new PCI manager
    pub fn new() -> Self {
        PciManager {
            devices: RwLock::new(BTreeMap::new()),
            device_drivers: RwLock::new(BTreeMap::new()),
        }
    }
    
    /// Enumerate all PCI devices  
    pub fn enumerate_all_devices(&self) -> Vec<PciDevice> {
        let devices = self.devices.read();
        devices.values().cloned().collect()
    }
    
    /// Scan PCI bus for devices
    pub fn scan_devices(&self) -> Result<usize, &'static str> {
        let mut device_count = 0;
        let mut devices = self.devices.write();
        
        for bus in 0..=255u8 {
            for device in 0..32u8 {
                for function in 0..8u8 {
                    // Quick check for device presence
                    let address = 0x80000000u32 |
                                ((bus as u32) << 16) |
                                ((device as u32) << 11) |
                                ((function as u32) << 8);
                    
                    let vendor_id = unsafe {
                        let mut config_address_port = PortWriteOnly::new(0xCF8);
                        let mut config_data_port: PortReadOnly<u32> = PortReadOnly::new(0xCFC);
                        
                        config_address_port.write(address);
                        config_data_port.read() & 0xFFFF
                    };
                    
                    if vendor_id == 0xFFFF {
                        continue;
                    }
                    
                    // Create device
                    match PciDevice::new(bus, device, function) {
                        Ok(pci_device) => {
                            devices.insert((bus, device, function), pci_device);
                            device_count += 1;
                        },
                        Err(_) => continue,
                    }
                    
                    // If function 0 doesn't exist, no need to check other functions
                    if function == 0 {
                        let header_type = unsafe {
                            let mut config_address_port = PortWriteOnly::new(0xCF8);
                            let mut config_data_port: PortReadOnly<u32> = PortReadOnly::new(0xCFC);
                            
                            config_address_port.write(address | PCI_CONFIG_HEADER_TYPE as u32);
                            (config_data_port.read() >> 16) & 0xFF
                        };
                        
                        if header_type & 0x80 == 0 {
                            break; // Single function device
                        }
                    }
                }
            }
        }
        
        Ok(device_count)
    }
    
    /// Get device info by coordinates
    pub fn get_device_info(&self, bus: u8, device: u8, function: u8) -> Option<(u16, u16, u8)> {
        let devices = self.devices.read();
        devices.get(&(bus, device, function)).map(|dev| (dev.vendor_id, dev.device_id, dev.class_code))
    }
    
    /// Register device driver
    pub fn register_driver(&self, vendor_id: u16, device_id: u16, driver_name: String) {
        let mut drivers = self.device_drivers.write();
        drivers.insert((vendor_id, device_id), driver_name);
    }
    
    /// Get statistics
    pub fn get_stats(&self) -> PciStats {
        let devices = self.devices.read();
        let mut stats = PciStats {
            total_devices: devices.len(),
            devices_by_class: BTreeMap::new(),
            msix_devices: 0,
            dma_engines: 0,
            devices_found: devices.len() as u32,
            dma_transfers: 0, // Would be tracked in actual implementation
            interrupts_handled: 0, // Would be tracked in actual implementation
            errors: 0, // Would be tracked in actual implementation
        };
        
        for device in devices.values() {
            let class_key = (device.class_code, device.subclass);
            *stats.devices_by_class.entry(class_key).or_insert(0) += 1;
            
            if device.msix_capability.is_some() {
                stats.msix_devices += 1;
            }
            
            stats.dma_engines += device.dma_engines.len();
        }
        
        stats
    }
}

/// PCI statistics
#[derive(Debug)]
pub struct PciStats {
    pub total_devices: usize,
    pub devices_by_class: BTreeMap<(u8, u8), usize>,
    pub msix_devices: usize,
    pub dma_engines: usize,
    pub devices_found: u32,
    pub dma_transfers: u64,
    pub interrupts_handled: u64,
    pub errors: u64,
}

impl Default for PciStats {
    fn default() -> Self {
        Self {
            total_devices: 0,
            devices_by_class: BTreeMap::new(),
            msix_devices: 0,
            dma_engines: 0,
            devices_found: 0,
            dma_transfers: 0,
            interrupts_handled: 0,
            errors: 0,
        }
    }
}

/// Global PCI manager
static mut PCI_MANAGER: Option<PciManager> = None;

/// Initialize PCI subsystem
pub fn init_pci() -> Result<(), &'static str> {
    let manager = PciManager::new();
    let _device_count = manager.scan_devices()?;
    
    unsafe {
        PCI_MANAGER = Some(manager);
    }
    
    Ok(())
}

/// Get PCI manager
pub fn get_pci_manager() -> Option<&'static PciManager> {
    unsafe { PCI_MANAGER.as_ref() }
}

/// Convenience functions for PCI configuration space access

/// Read 16-bit value from PCI configuration space
pub fn pci_read_config16(bus: u8, device: u8, function: u8, offset: u8) -> u16 {
    let address = 0x80000000 | ((bus as u32) << 16) | ((device as u32) << 11) | 
                  ((function as u32) << 8) | ((offset as u32) & 0xFC);
    
    unsafe {
        crate::arch::x86_64::port::outl(0xCF8, address);
        let value = crate::arch::x86_64::port::inl(0xCFC);
        ((value >> ((offset & 2) * 8)) & 0xFFFF) as u16
    }
}

/// Write 16-bit value to PCI configuration space
pub fn pci_write_config16(bus: u8, device: u8, function: u8, offset: u8, value: u16) {
    let address = 0x80000000 | ((bus as u32) << 16) | ((device as u32) << 11) | 
                  ((function as u32) << 8) | ((offset as u32) & 0xFC);
    
    unsafe {
        crate::arch::x86_64::port::outl(0xCF8, address);
        let mut reg_value = crate::arch::x86_64::port::inl(0xCFC);
        let shift = (offset & 2) * 8;
        reg_value = (reg_value & !(0xFFFF << shift)) | ((value as u32) << shift);
        crate::arch::x86_64::port::outl(0xCFC, reg_value);
    }
}

/// Read 32-bit value from PCI configuration space
pub fn pci_read_config32(bus: u8, device: u8, function: u8, offset: u8) -> u32 {
    let address = 0x80000000 | ((bus as u32) << 16) | ((device as u32) << 11) | 
                  ((function as u32) << 8) | ((offset as u32) & 0xFC);
    
    unsafe {
        crate::arch::x86_64::port::outl(0xCF8, address);
        crate::arch::x86_64::port::inl(0xCFC)
    }
}

/// Write 32-bit value to PCI configuration space
pub fn pci_write_config32(bus: u8, device: u8, function: u8, offset: u8, value: u32) {
    let address = 0x80000000 | ((bus as u32) << 16) | ((device as u32) << 11) | 
                  ((function as u32) << 8) | ((offset as u32) & 0xFC);
    
    unsafe {
        crate::arch::x86_64::port::outl(0xCF8, address);
        crate::arch::x86_64::port::outl(0xCFC, value);
    }
}

/// Find device by class and subclass
pub fn find_device_by_class(class: u8, subclass: u8) -> Option<PciDevice> {
    if let Some(manager) = get_pci_manager() {
        let devices = manager.devices.read();
        for device in devices.values() {
            if device.class_code == class && device.subclass == subclass {
                // Create a new PciDevice instance with the essential fields
                return Some(PciDevice {
                    bus: device.bus,
                    device: device.device,
                    function: device.function,
                    vendor_id: device.vendor_id,
                    device_id: device.device_id,
                    class_code: device.class_code,
                    subclass: device.subclass,
                    prog_if: device.prog_if,
                    revision_id: device.revision_id,
                    header_type: device.header_type,
                    interrupt_line: device.interrupt_line,
                    interrupt_pin: device.interrupt_pin,
                    bars: device.bars.clone(),
                    capabilities: device.capabilities.clone(),
                    msix_capability: device.msix_capability.clone(),
                    msix_table: device.msix_table.clone(),
                    msix_enabled: AtomicBool::new(device.msix_enabled.load(Ordering::Relaxed)),
                    dma_engines: Vec::new(), // Can't clone Mutex easily, use empty vec
                    driver_data: device.driver_data,
                });
            }
        }
    }
    None
}

/// Scan PCI bus and return list of all devices
pub fn scan_pci_bus() -> Vec<PciDevice> {
    let mut devices = Vec::new();
    
    // Scan all possible PCI bus/device/function combinations
    for bus in 0..=255u8 {
        for device in 0..32u8 {
            for function in 0..8u8 {
                if let Ok(pci_dev) = PciDevice::new(bus, device, function) {
                    // Check if device exists (vendor ID != 0xFFFF)
                    if pci_dev.vendor_id != 0xFFFF {
                        devices.push(pci_dev);
                    }
                }
            }
        }
    }
    
    devices
}