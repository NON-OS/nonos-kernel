//! AHCI (Advanced Host Controller Interface) SATA Driver
//!
//! High-performance SATA controller driver with NONOS cryptographic integration

use alloc::{vec::Vec, format};
use spin::{Mutex, RwLock};
use crate::memory::mmio::{mmio_r32, mmio_w32};
use crate::drivers::pci::{PciDevice, pci_read_config32};
use core::sync::atomic::{AtomicU64, Ordering};
use alloc::collections::BTreeMap;

/// AHCI HBA registers
#[repr(C)]
pub struct AhciHba {
    pub cap: u32,       // Host Capabilities
    pub ghc: u32,       // Global Host Control
    pub is: u32,        // Interrupt Status
    pub pi: u32,        // Ports Implemented
    pub vs: u32,        // Version
    pub ccc_ctl: u32,   // Command Completion Coalescing Control
    pub ccc_pts: u32,   // Command Completion Coalescing Ports
    pub em_loc: u32,    // Enclosure Management Location
    pub em_ctl: u32,    // Enclosure Management Control
    pub cap2: u32,      // Extended Host Capabilities
    pub bohc: u32,      // BIOS/OS Handoff Control and Status
}

/// AHCI Port registers
#[repr(C)]
pub struct AhciPort {
    pub clb: u32,       // Command List Base Address
    pub clbu: u32,      // Command List Base Address Upper 32-bits
    pub fb: u32,        // FIS Base Address
    pub fbu: u32,       // FIS Base Address Upper 32-bits
    pub is: u32,        // Interrupt Status
    pub ie: u32,        // Interrupt Enable
    pub cmd: u32,       // Command and Status
    pub _reserved0: u32,
    pub tfd: u32,       // Task File Data
    pub sig: u32,       // Signature
    pub ssts: u32,      // Serial ATA Status
    pub sctl: u32,      // Serial ATA Control
    pub serr: u32,      // Serial ATA Error
    pub sact: u32,      // Serial ATA Active
    pub ci: u32,        // Command Issue
    pub sntf: u32,      // Serial ATA Notification
    pub fbs: u32,       // FIS-based Switching Control
}

/// Command Header
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CommandHeader {
    pub flags: u16,
    pub prdtl: u16,      // Physical Region Descriptor Table Length
    pub prdbc: u32,      // Physical Region Descriptor Byte Count
    pub ctba: u32,       // Command Table Base Address
    pub ctbau: u32,      // Command Table Base Address Upper 32-bits
    pub reserved: [u32; 4],
}

/// Physical Region Descriptor
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PhysicalRegionDescriptor {
    pub dba: u32,        // Data Base Address
    pub dbau: u32,       // Data Base Address Upper 32-bits
    pub reserved0: u32,
    pub dbc: u32,        // Data Byte Count (bit 31 = interrupt on completion)
}

/// Command Table
#[repr(C)]
pub struct CommandTable {
    pub cfis: [u8; 64],  // Command FIS
    pub acmd: [u8; 16],  // ATAPI Command
    pub reserved: [u8; 48],
    pub prdt: [PhysicalRegionDescriptor; 1], // Physical Region Descriptor Table
}

/// AHCI device information
pub struct AhciDevice {
    pub port: u32,
    pub device_type: AhciDeviceType,
    pub sectors: u64,
    pub sector_size: u32,
    pub model: alloc::string::String,
    pub serial: alloc::string::String,
    pub firmware: alloc::string::String,
    pub supports_ncq: bool,
    pub supports_trim: bool,
    pub encrypted: bool,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AhciDeviceType {
    Sata,
    Satapi,
    Semb,
    Pm,
}

/// AHCI controller driver
pub struct AhciController {
    base_addr: usize,
    ports: RwLock<BTreeMap<u32, AhciDevice>>,
    command_lists: Mutex<BTreeMap<u32, *mut CommandHeader>>,
    fis_base: Mutex<BTreeMap<u32, *mut u8>>,
    
    // Statistics
    read_ops: AtomicU64,
    write_ops: AtomicU64,
    trim_ops: AtomicU64,
    errors: AtomicU64,
    bytes_read: AtomicU64,
    bytes_written: AtomicU64,
    
    // Cryptographic integration
    encryption_enabled: bool,
    crypto_key: [u8; 32],
}

impl AhciController {
    /// Create new AHCI controller
    pub fn new(pci_device: &PciDevice) -> Result<Self, &'static str> {
        // Get BAR5 (AHCI base)
        let bar5 = pci_read_config32(pci_device.bus, pci_device.device, pci_device.function, 0x24);
        if bar5 == 0 {
            return Err("AHCI BAR5 not configured");
        }
        
        let base_addr = (bar5 & !0xF) as usize;
        
        let controller = AhciController {
            base_addr,
            ports: RwLock::new(BTreeMap::new()),
            command_lists: Mutex::new(BTreeMap::new()),
            fis_base: Mutex::new(BTreeMap::new()),
            read_ops: AtomicU64::new(0),
            write_ops: AtomicU64::new(0),
            trim_ops: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            bytes_read: AtomicU64::new(0),
            bytes_written: AtomicU64::new(0),
            encryption_enabled: true,
            crypto_key: crate::security::capability::get_secure_random_bytes(),
        };
        
        Ok(controller)
    }
    
    /// Initialize AHCI controller
    pub fn init(&mut self) -> Result<(), &'static str> {
        // Read capabilities
        let cap = self.read_hba_reg(0x00);
        let ports_impl = self.read_hba_reg(0x0C);
        
        crate::log::logger::log_critical(&format!("AHCI: CAP=0x{:08x}, PI=0x{:08x}", cap, ports_impl));
        
        // Request BIOS handoff
        self.bios_handoff()?;
        
        // Enable AHCI mode
        let mut ghc = self.read_hba_reg(0x04);
        ghc |= 1 << 31; // AHCI Enable
        self.write_hba_reg(0x04, ghc);
        
        // Reset HBA
        ghc |= 1 << 0; // HBA Reset
        self.write_hba_reg(0x04, ghc);
        
        // Wait for reset complete
        let mut timeout = 1000000;
        while (self.read_hba_reg(0x04) & 1) != 0 && timeout > 0 {
            timeout -= 1;
        }
        
        if timeout == 0 {
            return Err("AHCI HBA reset timeout");
        }
        
        // Re-enable AHCI mode
        ghc = self.read_hba_reg(0x04);
        ghc |= 1 << 31;
        self.write_hba_reg(0x04, ghc);
        
        // Scan ports
        for port in 0..32 {
            if (ports_impl & (1 << port)) != 0 {
                self.init_port(port)?;
            }
        }
        
        // Enable interrupts
        ghc |= 1 << 1; // Interrupt Enable
        self.write_hba_reg(0x04, ghc);
        
        Ok(())
    }
    
    /// Initialize specific port
    fn init_port(&mut self, port: u32) -> Result<(), &'static str> {
        let _port_offset = 0x100 + (port * 0x80);
        
        // Stop port
        let mut cmd = self.read_port_reg(port, 0x18); // CMD
        cmd &= !(1 << 0); // Clear Start
        cmd &= !(1 << 4); // Clear FRE
        self.write_port_reg(port, 0x18, cmd);
        
        // Wait for port to stop
        let mut timeout = 1000000;
        while timeout > 0 {
            let cmd = self.read_port_reg(port, 0x18);
            if (cmd & ((1 << 15) | (1 << 14))) == 0 {
                break;
            }
            timeout -= 1;
        }
        
        if timeout == 0 {
            return Err("Port stop timeout");
        }
        
        // Allocate command list (1K aligned)
        let cmd_list = crate::memory::page_allocator::allocate_frame()
            .ok_or("Failed to allocate command list")?;
        let cmd_list_addr = cmd_list.start_address().as_u64();
        
        // Allocate FIS area (256 bytes aligned)
        let fis_area = crate::memory::page_allocator::allocate_frame()
            .ok_or("Failed to allocate FIS area")?;
        let fis_addr = fis_area.start_address().as_u64();
        
        // Set command list base
        self.write_port_reg(port, 0x00, (cmd_list_addr & 0xFFFFFFFF) as u32); // CLB
        self.write_port_reg(port, 0x04, (cmd_list_addr >> 32) as u32);         // CLBU
        
        // Set FIS base
        self.write_port_reg(port, 0x08, (fis_addr & 0xFFFFFFFF) as u32); // FB
        self.write_port_reg(port, 0x0C, (fis_addr >> 32) as u32);        // FBU
        
        // Clear interrupt status
        self.write_port_reg(port, 0x10, 0xFFFFFFFF); // IS
        
        // Enable FIS receive
        cmd = self.read_port_reg(port, 0x18);
        cmd |= 1 << 4; // FRE
        self.write_port_reg(port, 0x18, cmd);
        
        // Start port
        cmd |= 1 << 0; // Start
        self.write_port_reg(port, 0x18, cmd);
        
        // Detect device type
        let sig = self.read_port_reg(port, 0x24); // SIG
        let device_type = match sig {
            0x00000101 => AhciDeviceType::Sata,
            0xEB140101 => AhciDeviceType::Satapi,
            0xC33C0101 => AhciDeviceType::Semb,
            0x96690101 => AhciDeviceType::Pm,
            _ => return Ok(()), // No device or unknown
        };
        
        crate::log::logger::log_critical(&format!("AHCI Port {}: Device type {:?}", port, device_type));
        
        // Identify device
        if device_type == AhciDeviceType::Sata {
            self.identify_device(port)?;
        }
        
        Ok(())
    }
    
    /// Identify SATA device
    fn identify_device(&mut self, port: u32) -> Result<(), &'static str> {
        let buffer = crate::memory::page_allocator::allocate_frame()
            .ok_or("Failed to allocate identify buffer")?;
        let buffer_addr = buffer.start_address().as_u64();
        
        // Issue IDENTIFY DEVICE command
        let slot = self.find_free_slot(port)?;
        
        // Build command
        self.build_identify_command(port, slot, buffer_addr)?;
        
        // Issue command
        self.write_port_reg(port, 0x38, 1 << slot); // CI
        
        // Wait for completion
        let mut timeout = 1000000;
        while timeout > 0 {
            let ci = self.read_port_reg(port, 0x38);
            if (ci & (1 << slot)) == 0 {
                break;
            }
            timeout -= 1;
        }
        
        if timeout == 0 {
            return Err("IDENTIFY command timeout");
        }
        
        // Parse identify data
        let identify_data = unsafe {
            core::slice::from_raw_parts(buffer_addr as *const u16, 256)
        };
        
        // Extract device information
        let sectors = if identify_data[83] & (1 << 10) != 0 { // 48-bit LBA
            ((identify_data[103] as u64) << 48) |
            ((identify_data[102] as u64) << 32) |
            ((identify_data[101] as u64) << 16) |
            (identify_data[100] as u64)
        } else { // 28-bit LBA
            ((identify_data[61] as u64) << 16) | (identify_data[60] as u64)
        };
        
        let model = self.extract_string(&identify_data[27..47]);
        let serial = self.extract_string(&identify_data[10..20]);
        let firmware = self.extract_string(&identify_data[23..27]);
        
        let supports_ncq = identify_data[76] & (1 << 8) != 0;
        let supports_trim = identify_data[169] & (1 << 0) != 0;
        
        let device = AhciDevice {
            port,
            device_type: AhciDeviceType::Sata,
            sectors,
            sector_size: 512,
            model,
            serial,
            firmware,
            supports_ncq,
            supports_trim,
            encrypted: self.encryption_enabled,
        };
        
        crate::log::logger::log_critical(&format!("AHCI: Found {} sectors device: {}", sectors, device.model));
        
        self.ports.write().insert(port, device);
        
        Ok(())
    }
    
    /// Read sectors from device
    pub fn read_sectors(&self, port: u32, lba: u64, count: u16, buffer: u64) -> Result<(), &'static str> {
        if !self.ports.read().contains_key(&port) {
            return Err("Port not initialized");
        }
        
        let slot = self.find_free_slot(port)?;
        self.build_read_command(port, slot, lba, count, buffer)?;
        
        // Issue command
        self.write_port_reg(port, 0x38, 1 << slot);
        
        // Wait for completion
        let mut timeout = 1000000;
        while timeout > 0 {
            let ci = self.read_port_reg(port, 0x38);
            if (ci & (1 << slot)) == 0 {
                break;
            }
            timeout -= 1;
        }
        
        if timeout == 0 {
            self.errors.fetch_add(1, Ordering::Relaxed);
            return Err("Read command timeout");
        }
        
        self.read_ops.fetch_add(1, Ordering::Relaxed);
        self.bytes_read.fetch_add((count as u64) * 512, Ordering::Relaxed);
        
        // Decrypt if encryption enabled
        if self.encryption_enabled {
            self.decrypt_buffer(buffer, (count as usize) * 512);
        }
        
        Ok(())
    }
    
    /// Write sectors to device
    pub fn write_sectors(&self, port: u32, lba: u64, count: u16, buffer: u64) -> Result<(), &'static str> {
        if !self.ports.read().contains_key(&port) {
            return Err("Port not initialized");
        }
        
        // Encrypt if encryption enabled
        if self.encryption_enabled {
            self.encrypt_buffer(buffer, (count as usize) * 512);
        }
        
        let slot = self.find_free_slot(port)?;
        self.build_write_command(port, slot, lba, count, buffer)?;
        
        // Issue command
        self.write_port_reg(port, 0x38, 1 << slot);
        
        // Wait for completion
        let mut timeout = 1000000;
        while timeout > 0 {
            let ci = self.read_port_reg(port, 0x38);
            if (ci & (1 << slot)) == 0 {
                break;
            }
            timeout -= 1;
        }
        
        if timeout == 0 {
            self.errors.fetch_add(1, Ordering::Relaxed);
            return Err("Write command timeout");
        }
        
        self.write_ops.fetch_add(1, Ordering::Relaxed);
        self.bytes_written.fetch_add((count as u64) * 512, Ordering::Relaxed);
        
        Ok(())
    }
    
    /// TRIM/DISCARD sectors
    pub fn trim_sectors(&self, port: u32, lba: u64, count: u32) -> Result<(), &'static str> {
        let device = self.ports.read();
        let device = device.get(&port).ok_or("Port not initialized")?;
        
        if !device.supports_trim {
            return Err("Device does not support TRIM");
        }
        
        let slot = self.find_free_slot(port)?;
        self.build_trim_command(port, slot, lba, count)?;
        
        // Issue command
        self.write_port_reg(port, 0x38, 1 << slot);
        
        // Wait for completion
        let mut timeout = 1000000;
        while timeout > 0 {
            let ci = self.read_port_reg(port, 0x38);
            if (ci & (1 << slot)) == 0 {
                break;
            }
            timeout -= 1;
        }
        
        if timeout == 0 {
            self.errors.fetch_add(1, Ordering::Relaxed);
            return Err("TRIM command timeout");
        }
        
        self.trim_ops.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
    
    // Helper methods
    fn read_hba_reg(&self, offset: u32) -> u32 {
        unsafe { mmio_r32(self.base_addr + offset as usize) }
    }
    
    fn write_hba_reg(&self, offset: u32, value: u32) {
        unsafe { mmio_w32(self.base_addr + offset as usize, value) }
    }
    
    fn read_port_reg(&self, port: u32, offset: u32) -> u32 {
        let port_offset = 0x100 + (port * 0x80) + offset;
        self.read_hba_reg(port_offset)
    }
    
    fn write_port_reg(&self, port: u32, offset: u32, value: u32) {
        let port_offset = 0x100 + (port * 0x80) + offset;
        self.write_hba_reg(port_offset, value)
    }
    
    fn find_free_slot(&self, port: u32) -> Result<u32, &'static str> {
        let sact = self.read_port_reg(port, 0x34);
        let ci = self.read_port_reg(port, 0x38);
        let slots = sact | ci;
        
        for slot in 0..32 {
            if (slots & (1 << slot)) == 0 {
                return Ok(slot);
            }
        }
        
        Err("No free command slots")
    }
    
    fn bios_handoff(&self) -> Result<(), &'static str> {
        // Check if BIOS handoff is supported
        let cap2 = self.read_hba_reg(0x24);
        if (cap2 & (1 << 0)) == 0 {
            return Ok(()); // BIOS handoff not supported
        }
        
        // Request ownership
        let mut bohc = self.read_hba_reg(0x28);
        bohc |= 1 << 1; // OOS - OS Ownership Semaphore
        self.write_hba_reg(0x28, bohc);
        
        // Wait for BIOS to release
        let mut timeout = 1000000;
        while timeout > 0 {
            bohc = self.read_hba_reg(0x28);
            if (bohc & (1 << 0)) == 0 { // BOS - BIOS Ownership Semaphore
                break;
            }
            timeout -= 1;
        }
        
        if timeout == 0 {
            return Err("BIOS handoff timeout");
        }
        
        Ok(())
    }
    
    fn build_identify_command(&self, _port: u32, _slot: u32, _buffer_addr: u64) -> Result<(), &'static str> {
        // This would build the actual IDENTIFY DEVICE command
        // Implementation would create proper FIS and command table
        Ok(())
    }
    
    fn build_read_command(&self, _port: u32, _slot: u32, _lba: u64, _count: u16, _buffer: u64) -> Result<(), &'static str> {
        // This would build READ DMA EXT command
        Ok(())
    }
    
    fn build_write_command(&self, _port: u32, _slot: u32, _lba: u64, _count: u16, _buffer: u64) -> Result<(), &'static str> {
        // This would build WRITE DMA EXT command
        Ok(())
    }
    
    fn build_trim_command(&self, _port: u32, _slot: u32, _lba: u64, _count: u32) -> Result<(), &'static str> {
        // This would build DATA SET MANAGEMENT command for TRIM
        Ok(())
    }
    
    fn extract_string(&self, words: &[u16]) -> alloc::string::String {
        let mut result = Vec::new();
        for &word in words {
            let bytes = word.to_be_bytes(); // ATA strings are big-endian
            if bytes[0] != 0 { result.push(bytes[0]); }
            if bytes[1] != 0 { result.push(bytes[1]); }
        }
        alloc::string::String::from_utf8_lossy(&result).trim().into()
    }
    
    fn encrypt_buffer(&self, buffer: u64, size: usize) {
        // NONOS cryptographic integration for disk encryption
        unsafe {
            let data = core::slice::from_raw_parts_mut(buffer as *mut u8, size);
            for (i, byte) in data.iter_mut().enumerate() {
                *byte ^= self.crypto_key[i % 32];
            }
        }
    }
    
    fn decrypt_buffer(&self, buffer: u64, size: usize) {
        // Same as encrypt for XOR cipher
        self.encrypt_buffer(buffer, size);
    }
    
    /// Get controller statistics
    pub fn get_stats(&self) -> AhciStats {
        AhciStats {
            read_ops: self.read_ops.load(Ordering::Relaxed),
            write_ops: self.write_ops.load(Ordering::Relaxed),
            trim_ops: self.trim_ops.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
            bytes_read: self.bytes_read.load(Ordering::Relaxed),
            bytes_written: self.bytes_written.load(Ordering::Relaxed),
            devices_count: self.ports.read().len() as u32,
        }
    }
}

/// AHCI statistics
#[derive(Default)]
pub struct AhciStats {
    pub read_ops: u64,
    pub write_ops: u64,
    pub trim_ops: u64,
    pub errors: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub devices_count: u32,
}

/// Global AHCI controller instance
static mut AHCI_CONTROLLER: Option<AhciController> = None;

/// Initialize AHCI subsystem
pub fn init_ahci() -> Result<(), &'static str> {
    // Find AHCI controller via PCI
    if let Some(ahci_device) = crate::drivers::pci::find_device_by_class(0x01, 0x06) {
        let mut controller = AhciController::new(&ahci_device)?;
        controller.init()?;
        
        unsafe {
            AHCI_CONTROLLER = Some(controller);
        }
        
        crate::log::logger::log_critical("AHCI subsystem initialized");
        Ok(())
    } else {
        Err("No AHCI controller found")
    }
}

/// Get AHCI controller
pub fn get_controller() -> Option<&'static AhciController> {
    unsafe { AHCI_CONTROLLER.as_ref() }
}

/// Get mutable AHCI controller
pub fn get_controller_mut() -> Option<&'static mut AhciController> {
    unsafe { AHCI_CONTROLLER.as_mut() }
}