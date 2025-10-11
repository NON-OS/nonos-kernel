//! AHCI (Advanced Host Controller Interface) SATA Driver
//! References: AHCI 1.3.1 Spec; ATA/ATAPI-8 ACS (Data Set Management / TRIM)

use alloc::{vec::Vec, format};
use spin::{Mutex, RwLock};
use core::sync::atomic::{AtomicU64, Ordering};
use alloc::collections::BTreeMap;
use x86_64::{VirtAddr, PhysAddr};
use crate::memory::mmio::{mmio_r32, mmio_w32};
use crate::drivers::pci::{PciDevice, pci_read_config32};
use crate::memory::dma::alloc_dma_coherent;

/// HBA registers offsets
const HBA_CAP: u32 = 0x00;
const HBA_GHC: u32 = 0x04;
const HBA_IS: u32  = 0x08;
const HBA_PI: u32  = 0x0C;
const HBA_VS: u32  = 0x10;
const HBA_CAP2: u32 = 0x24;
const HBA_BOHC: u32 = 0x28;

/// Per-port register offsets
const PORT_CLB: u32  = 0x00;
const PORT_CLBU: u32 = 0x04;
const PORT_FB: u32   = 0x08;
const PORT_FBU: u32  = 0x0C;
const PORT_IS: u32   = 0x10;
const PORT_IE: u32   = 0x14;
const PORT_CMD: u32  = 0x18;
const PORT_TFD: u32  = 0x20;
const PORT_SIG: u32  = 0x24;
const PORT_SSTS: u32 = 0x28;
const PORT_SCTL: u32 = 0x2C;
const PORT_SERR: u32 = 0x30;
const PORT_SACT: u32 = 0x34;
const PORT_CI: u32   = 0x38;

/// PxCMD bits
const CMD_ST: u32   = 1 << 0;  // Start
const CMD_FRE: u32  = 1 << 4;  // FIS Receive Enable
const CMD_FR: u32   = 1 << 14; // FIS Receive Running
const CMD_CR: u32   = 1 << 15; // Command List Running

/// PxIS bits (subset)
const IS_TFES: u32 = 1 << 30; // Task File Error

/// FIS types
const FIS_TYPE_REG_H2D: u8 = 0x27;

/// ATA commands
const ATA_CMD_IDENTIFY: u8      = 0xEC;
const ATA_CMD_READ_DMA_EXT: u8  = 0x25;
const ATA_CMD_WRITE_DMA_EXT: u8 = 0x35;
const ATA_CMD_DSM: u8           = 0x06; // Data Set Management
/// DSM subcommands (Features low)
const DSM_TRIM: u8 = 0x01; // TRIM operation

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

/// Command Header (per AHCI spec 4.2.2)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct CommandHeader {
    pub flags: u16,     // bits: 4:0 CFL, 5 A, 6 W, 7 P, 8 R, 9 B, 10 C, 15:11 Rsvd
    pub prdtl: u16,     // PRDT length (entries)
    pub prdbc: u32,     // PRDT byte count
    pub ctba: u32,      // Command Table Base (low 32)
    pub ctbau: u32,     // Command Table Base (high 32)
    pub reserved: [u32; 4],
}

/// Physical Region Descriptor (per AHCI spec 4.2.3)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PhysicalRegionDescriptor {
    pub dba: u32,        // Data Base Address
    pub dbau: u32,       // Data Base Address Upper 32-bits
    pub reserved0: u32,
    pub dbc: u32,        // Byte Count (bits 21:0), bit31=IOC
}

/// Command Table (1 PRD entry per slot; dbc supports up to 4MB)
#[repr(C, align(128))]
pub struct CommandTable {
    pub cfis: [u8; 64],  // Command FIS
    pub acmd: [u8; 16],  // ATAPI Command 
    pub reserved: [u8; 48],
    pub prdt: [PhysicalRegionDescriptor; 1],
}

/// Device information
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

/// Per-port DMA allocations
struct PortDma {
    // Command list (32 headers), 1KB aligned
    cl_dma_va: VirtAddr,
    cl_dma_pa: PhysAddr,
    cl_entries: *mut CommandHeader,

    // FIS receive area (256 bytes)
    fis_dma_va: VirtAddr,
    fis_dma_pa: PhysAddr,

    // Command tables (one per slot, 32 slots). Allocate 32×256B blocks.
    ct_dma_va: VirtAddr,
    ct_dma_pa: PhysAddr,
    ct_slot_size: usize, // 256
}

impl PortDma {
    fn new() -> Result<Self, &'static str> {
        let (cl_va, cl_pa) = alloc_dma_coherent(1024)?;
        unsafe { core::ptr::write_bytes(cl_va.as_mut_ptr::<u8>(), 0, 1024); }

        let (fis_va, fis_pa) = alloc_dma_coherent(256)?;
        unsafe { core::ptr::write_bytes(fis_va.as_mut_ptr::<u8>(), 0, 256); }

        let (ct_va, ct_pa) = alloc_dma_coherent(256 * 32)?;
        unsafe { core::ptr::write_bytes(ct_va.as_mut_ptr::<u8>(), 0, 256 * 32); }

        Ok(Self {
            cl_dma_va: cl_va,
            cl_dma_pa: cl_pa,
            cl_entries: cl_va.as_mut_ptr::<CommandHeader>(),
            fis_dma_va: fis_va,
            fis_dma_pa: fis_pa,
            ct_dma_va: ct_va,
            ct_dma_pa: ct_pa,
            ct_slot_size: 256,
        })
    }

    #[inline]
    fn ct_for_slot(&self, slot: u32) -> (*mut CommandTable, PhysAddr) {
        let off = self.ct_slot_size as u64 * slot as u64;
        let va = unsafe { self.ct_dma_va.as_mut_ptr::<u8>().add(off as usize) as *mut CommandTable };
        let pa = PhysAddr::new(self.ct_dma_pa.as_u64() + off);
        (va, pa)
    }
}

/// AHCI controller driver
pub struct AhciController {
    base_addr: usize,
    ports: RwLock<BTreeMap<u32, AhciDevice>>,
    port_dma: Mutex<BTreeMap<u32, PortDma>>,

    // Statistics
    read_ops: AtomicU64,
    write_ops: AtomicU64,
    trim_ops: AtomicU64,
    errors: AtomicU64,
    bytes_read: AtomicU64,
    bytes_written: AtomicU64,

    // Cryptographic integration (XOR demo)
    encryption_enabled: bool,
    crypto_key: [u8; 32],
}

impl AhciController {
    /// Create new AHCI controller
    pub fn new(pci_device: &PciDevice) -> Result<Self, &'static str> {
        // Get BAR5 (AHCI MMIO base)
        let bar5 = pci_read_config32(pci_device.bus, pci_device.device, pci_device.function, 0x24);
        if bar5 == 0 {
            return Err("AHCI BAR5 not configured");
        }
        let base_addr = (bar5 & !0xF) as usize;

        Ok(AhciController {
            base_addr,
            ports: RwLock::new(BTreeMap::new()),
            port_dma: Mutex::new(BTreeMap::new()),
            read_ops: AtomicU64::new(0),
            write_ops: AtomicU64::new(0),
            trim_ops: AtomicU64::new(0),
            errors: AtomicU64::new(0),
            bytes_read: AtomicU64::new(0),
            bytes_written: AtomicU64::new(0),
            encryption_enabled: true,
            crypto_key: crate::security::capability::get_secure_random_bytes(),
        })
    }

    /// Initialize AHCI controller
    pub fn init(&mut self) -> Result<(), &'static str> {
        let cap = self.read_hba_reg(HBA_CAP);
        let ports_impl = self.read_hba_reg(HBA_PI);

        crate::log::logger::log_critical(&format!("AHCI: CAP=0x{:08x}, PI=0x{:08x}", cap, ports_impl));

        // BIOS handoff if supported
        self.bios_handoff()?;

        // Enable AHCI mode
        let mut ghc = self.read_hba_reg(HBA_GHC);
        ghc |= 1 << 31; // AE
        self.write_hba_reg(HBA_GHC, ghc);

        // Reset HBA
        ghc |= 1 << 0; // HR
        self.write_hba_reg(HBA_GHC, ghc);

        // Wait for reset complete
        if !self.wait_while(|| (self.read_hba_reg(HBA_GHC) & 1) != 0, 1_000_000) {
            return Err("AHCI HBA reset timeout");
        }

        // Re-enable AHCI mode
        ghc = self.read_hba_reg(HBA_GHC) | (1 << 31);
        self.write_hba_reg(HBA_GHC, ghc);

        // Initialize ports
        for port in 0..32 {
            if (ports_impl & (1 << port)) != 0 {
                if let Err(e) = self.init_port(port) {
                    crate::log::logger::log_critical(&format!("AHCI: Port {} init failed: {}", port, e));
                }
            }
        }

        // Enable interrupts globally
        ghc |= 1 << 1; // IE
        self.write_hba_reg(HBA_GHC, ghc);
        Ok(())
    }

    /// Initialize specific port
    fn init_port(&mut self, port: u32) -> Result<(), &'static str> {
        // Stop port (clear ST and FRE, wait for CR/FR clear)
        self.stop_port(port)?;

        // Allocate DMA buffers
        let pdma = PortDma::new()?;
        // Program CLB/FB
        self.write_port_reg(port, PORT_CLB, (pdma.cl_dma_pa.as_u64() & 0xFFFF_FFFF) as u32);
        self.write_port_reg(port, PORT_CLBU, (pdma.cl_dma_pa.as_u64() >> 32) as u32);
        self.write_port_reg(port, PORT_FB, (pdma.fis_dma_pa.as_u64() & 0xFFFF_FFFF) as u32);
        self.write_port_reg(port, PORT_FBU, (pdma.fis_dma_pa.as_u64() >> 32) as u32);

        // Clear interrupt status and errors
        self.write_port_reg(port, PORT_IS, 0xFFFF_FFFF);
        self.write_port_reg(port, PORT_SERR, 0xFFFF_FFFF);

        // Enable FIS receive then start
        let mut cmd = self.read_port_reg(port, PORT_CMD);
        cmd |= CMD_FRE;
        self.write_port_reg(port, PORT_CMD, cmd);

        cmd |= CMD_ST;
        self.write_port_reg(port, PORT_CMD, cmd);

        // Detect device signature
        let sig = self.read_port_reg(port, PORT_SIG);
        let device_type = match sig {
            0x0000_0101 => AhciDeviceType::Sata,
            0xEB14_0101 => AhciDeviceType::Satapi,
            0xC33C_0101 => AhciDeviceType::Semb,
            0x9669_0101 => AhciDeviceType::Pm,
            _ => {
                self.port_dma.lock().insert(port, pdma);
                return Ok(());
            }
        };

        crate::log::logger::log_critical(&format!("AHCI Port {}: Device type {:?}", port, device_type));

        // Keep DMA allocations recorded
        self.port_dma.lock().insert(port, pdma);

        // Identify device if SATA
        if device_type == AhciDeviceType::Sata {
            self.identify_device(port)?;
        }

        Ok(())
    }

    /// Stop a port safely
    fn stop_port(&self, port: u32) -> Result<(), &'static str> {
        let mut cmd = self.read_port_reg(port, PORT_CMD);
        cmd &= !CMD_ST;
        self.write_port_reg(port, PORT_CMD, cmd);

        // Wait for CR clear
        if !self.wait_while(|| (self.read_port_reg(port, PORT_CMD) & CMD_CR) != 0, 1_000_000) {
            return Err("Port command list runner didn't stop");
        }

        // Disable FIS receive
        cmd = self.read_port_reg(port, PORT_CMD) & !CMD_FRE;
        self.write_port_reg(port, PORT_CMD, cmd);

        // Wait for FR clear
        if !self.wait_while(|| (self.read_port_reg(port, PORT_CMD) & CMD_FR) != 0, 1_000_000) {
            return Err("Port FIS runner didn't stop");
        }
        Ok(())
    }

    /// Identify SATA device
    fn identify_device(&mut self, port: u32) -> Result<(), &'static str> {
        // Buffer for 512 bytes
        let (buf_va, buf_pa) = alloc_dma_coherent(512)?;
        unsafe { core::ptr::write_bytes(buf_va.as_mut_ptr::<u8>(), 0, 512); }

        let slot = self.find_free_slot(port)?;
        self.build_identify_command(port, slot, buf_pa)?;

        // Issue command
        self.write_port_reg(port, PORT_CI, 1 << slot);

        // Wait completion
        self.wait_complete_or_error(port, slot)?;

        // Parse identify data
        let identify_data = unsafe {
            core::slice::from_raw_parts(buf_va.as_ptr::<u16>(), 256)
        };

        let sectors = if identify_data[83] & (1 << 10) != 0 {
            ((identify_data[103] as u64) << 48) |
            ((identify_data[102] as u64) << 32) |
            ((identify_data[101] as u64) << 16) |
            (identify_data[100] as u64)
        } else {
            ((identify_data[61] as u64) << 16) | (identify_data[60] as u64)
        };

        let model = self.extract_string(&identify_data[27..47]);
        let serial = self.extract_string(&identify_data[10..20]);
        let firmware = self.extract_string(&identify_data[23..27]);

        let supports_ncq = identify_data[76] & (1 << 8) != 0;
        let supports_trim = (identify_data[169] & (1 << 0)) != 0;

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

        crate::log::logger::log_critical(&format!("AHCI: Port {} - {} sectors, model {}", port, sectors, device.model));

        self.ports.write().insert(port, device);
        Ok(())
    }

    /// Read sectors (48-bit LBA)
    pub fn read_sectors(&self, port: u32, lba: u64, count: u16, buffer_va: u64) -> Result<(), &'static str> {
        if !self.ports.read().contains_key(&port) {
            return Err("Port not initialized");
        }
        let slot = self.find_free_slot(port)?;
        self.build_read_command(port, slot, lba, count, PhysAddr::new(buffer_va))?;

        self.write_port_reg(port, PORT_CI, 1 << slot);
        self.wait_complete_or_error(port, slot)?;

        self.read_ops.fetch_add(1, Ordering::Relaxed);
        self.bytes_read.fetch_add((count as u64) * 512, Ordering::Relaxed);

        if self.encryption_enabled {
            self.decrypt_buffer(buffer_va, (count as usize) * 512);
        }
        Ok(())
    }

    /// Write sectors (48-bit LBA)
    pub fn write_sectors(&self, port: u32, lba: u64, count: u16, buffer_va: u64) -> Result<(), &'static str> {
        if !self.ports.read().contains_key(&port) {
            return Err("Port not initialized");
        }

        if self.encryption_enabled {
            self.encrypt_buffer(buffer_va, (count as usize) * 512);
        }

        let slot = self.find_free_slot(port)?;
        self.build_write_command(port, slot, lba, count, PhysAddr::new(buffer_va))?;

        self.write_port_reg(port, PORT_CI, 1 << slot);
        self.wait_complete_or_error(port, slot)?;

        self.write_ops.fetch_add(1, Ordering::Relaxed);
        self.bytes_written.fetch_add((count as u64) * 512, Ordering::Relaxed);
        Ok(())
    }

    /// DATA SET MANAGEMENT - TRIM one LBA range 
    ///
    /// lba: starting LBA
    /// count: number of sectors to discard
    pub fn trim_sectors(&self, port: u32, lba: u64, count: u32) -> Result<(), &'static str> {
        let devs = self.ports.read();
        let dev = devs.get(&port).ok_or("Port not initialized")?;
        if !dev.supports_trim {
            return Err("Device does not support TRIM");
        }
        drop(devs);

        if count == 0 {
            return Ok(());
        }

        // Each TRIM range descriptor is 8 bytes:
        // [0..5] = 48-bit LBA (little-endian)
        // [6..7] = 16-bit sector count (little-endian)
        // Max per descriptor: 0xFFFF sectors
        // Max descriptors per 512-byte block: 512 / 8 = 256

        let mut remaining = count as u64;
        let mut current_lba = lba;

        // Determine how many descriptors and blocks it need
        let total_desc = ((remaining + 0xFFFF - 1) / 0xFFFF) as usize;
        let blocks = ((total_desc + 255) / 256) as usize;
        let total_bytes = blocks * 512;

        // Allocate TRIM buffer
        let (buf_va, buf_pa) = alloc_dma_coherent(total_bytes)?;
        unsafe { core::ptr::write_bytes(buf_va.as_mut_ptr::<u8>(), 0, total_bytes); }

        // Fill descriptors
        let mut desc_written = 0usize;
        let mut ptr_u8 = buf_va.as_mut_ptr::<u8>();
        for _ in 0..blocks {
            let block_desc = core::cmp::min(256, total_desc - desc_written);
            for _ in 0..block_desc {
                let this_count = core::cmp::min(remaining, 0xFFFF);
                // LBA 48-bit LE
                unsafe {
                    // 6 bytes LBA little-endian
                    core::ptr::write(ptr_u8, (current_lba & 0xFF) as u8);
                    core::ptr::write(ptr_u8.add(1), ((current_lba >> 8) & 0xFF) as u8);
                    core::ptr::write(ptr_u8.add(2), ((current_lba >> 16) & 0xFF) as u8);
                    core::ptr::write(ptr_u8.add(3), ((current_lba >> 24) & 0xFF) as u8);
                    core::ptr::write(ptr_u8.add(4), ((current_lba >> 32) & 0xFF) as u8);
                    core::ptr::write(ptr_u8.add(5), ((current_lba >> 40) & 0xFF) as u8);

                    // Sector count 16-bit LE
                    let sc = this_count as u16;
                    core::ptr::write(ptr_u8.add(6), (sc & 0xFF) as u8);
                    core::ptr::write(ptr_u8.add(7), (sc >> 8) as u8);
                }

                // Advance
                current_lba = current_lba.checked_add(this_count).ok_or("LBA overflow in TRIM")?;
                remaining -= this_count;
                desc_written += 1;
                unsafe { ptr_u8 = ptr_u8.add(8); }
                if remaining == 0 { break; }
            }
        }

        // Build DSM/TRIM command
        let slot = self.find_free_slot(port)?;
        self.build_trim_command(port, slot, buf_pa, blocks as u16)?;

        // Issue command
        self.write_port_reg(port, PORT_CI, 1 << slot);

        // Wait for completion
        self.wait_complete_or_error(port, slot)?;

        self.trim_ops.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    // -------------------- Low-level helpers --------------------

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

    fn wait_while<F: Fn() -> bool>(&self, cond: F, mut iters: u32) -> bool {
        while iters > 0 {
            if !cond() { return true; }
            iters -= 1;
        }
        false
    }

    fn find_free_slot(&self, port: u32) -> Result<u32, &'static str> {
        let sact = self.read_port_reg(port, PORT_SACT);
        let ci = self.read_port_reg(port, PORT_CI);
        let slots = sact | ci;

        for slot in 0..32 {
            if (slots & (1 << slot)) == 0 {
                return Ok(slot);
            }
        }
        Err("No free command slots")
    }

    fn bios_handoff(&self) -> Result<(), &'static str> {
        let cap2 = self.read_hba_reg(HBA_CAP2);
        if (cap2 & (1 << 0)) == 0 {
            return Ok(());
        }

        // Request OS ownership
        let mut bohc = self.read_hba_reg(HBA_BOHC);
        bohc |= 1 << 1; // OOS
        self.write_hba_reg(HBA_BOHC, bohc);

        // Wait for BIOS ownership clear
        if !self.wait_while(|| (self.read_hba_reg(HBA_BOHC) & 1) != 0, 1_000_000) {
            return Err("BIOS handoff timeout");
        }
        Ok(())
    }

    fn wait_complete_or_error(&self, port: u32, slot: u32) -> Result<(), &'static str> {
        let mut timeout = 2_000_000; // loop budget
        loop {
            let ci = self.read_port_reg(port, PORT_CI);
            let is = self.read_port_reg(port, PORT_IS);
            let tfd = self.read_port_reg(port, PORT_TFD);

            if (ci & (1 << slot)) == 0 {
                // Clear per-port interrupt bits we handled
                self.write_port_reg(port, PORT_IS, is);

                // Check task file error
                if (is & IS_TFES) != 0 || (tfd & 0x01) != 0 {
                    self.errors.fetch_add(1, Ordering::Relaxed);
                    return Err("AHCI command TFES or ERR");
                }
                return Ok(());
            }

            if (is & IS_TFES) != 0 {
                self.write_port_reg(port, PORT_IS, is);
                self.errors.fetch_add(1, Ordering::Relaxed);
                return Err("AHCI TFES during command");
            }

            if timeout == 0 {
                self.errors.fetch_add(1, Ordering::Relaxed);
                return Err("AHCI command timeout");
            }
            timeout -= 1;
        }
    }

    /// H2D Register FIS for 48-bit LBA commands into CFIS
    fn fill_h2d_fis(&self, cfis: &mut [u8], cmd: u8, lba: u64, count: u16, is_write: bool) {
        for b in cfis.iter_mut() { *b = 0; }
        cfis[0] = FIS_TYPE_REG_H2D;
        cfis[1] = 1 << 7; // C = 1, PM port 0
        cfis[2] = cmd;
        // cfis[3] = featurel (set by caller if needed)

        // LBA[0..5]
        cfis[4] = (lba & 0xFF) as u8;
        cfis[5] = ((lba >> 8) & 0xFF) as u8;
        cfis[6] = ((lba >> 16) & 0xFF) as u8;
        cfis[7] = 0x40; // device (bit 6 = LBA mode)
        cfis[8] = ((lba >> 24) & 0xFF) as u8;
        cfis[9] = ((lba >> 32) & 0xFF) as u8;
        cfis[10] = ((lba >> 40) & 0xFF) as u8;

        // cfis[11] if needed

        // Sector count (low/high)
        cfis[12] = (count & 0xFF) as u8;
        cfis[13] = ((count >> 8) & 0xFF) as u8;

        // ICC, control
        cfis[14] = 0;
        cfis[15] = 0;

        // for IDENTIFY (0xEC)
        if cmd == ATA_CMD_IDENTIFY {
            cfis[4..=6].fill(0);
            cfis[8..=10].fill(0);
            cfis[12] = 0;
            cfis[13] = 0;
        }

        let _ = is_write;
    }

    fn hdr_flags_for(cfis_dwords: u16, is_write: bool) -> u16 {
        let mut flags = cfis_dwords & 0x1F; // CFL
        if is_write { flags |= 1 << 6; }     // W
        flags
    }

    fn setup_slot(&self, port: u32, slot: u32) -> Result<(*mut CommandHeader, *mut CommandTable, PhysAddr), &'static str> {
        let pdma = self.port_dma.lock();
        let pdma = pdma.get(&port).ok_or("Port DMA not initialized")?;

        // Command header pointer
        let ch = unsafe { pdma.cl_entries.add(slot as usize) };

        // Command table per-slot
        let (ct_ptr, ct_pa) = pdma.ct_for_slot(slot);
        Ok((ch, ct_ptr, ct_pa))
    }

    fn build_identify_command(&self, port: u32, slot: u32, buffer_pa: PhysAddr) -> Result<(), &'static str> {
        let (ch, ct_ptr, ct_pa) = self.setup_slot(port, slot)?;
        unsafe {
            core::ptr::write_bytes(ch, 0, 1);
            core::ptr::write_bytes(ct_ptr, 0, 1);

            (*ct_ptr).cfis.fill(0);
            self.fill_h2d_fis(&mut (*ct_ptr).cfis, ATA_CMD_IDENTIFY, 0, 0, false);

            (*ct_ptr).prdt[0].dba = (buffer_pa.as_u64() & 0xFFFF_FFFF) as u32;
            (*ct_ptr).prdt[0].dbau = (buffer_pa.as_u64() >> 32) as u32;
            (*ct_ptr).prdt[0].reserved0 = 0;
            (*ct_ptr).prdt[0].dbc = (512 - 1) as u32 | (1 << 31); // IOC

            (*ch).flags = Self::hdr_flags_for(5, false); // CFIS length=5 dwords
            (*ch).prdtl = 1;
            (*ch).prdbc = 0;
            (*ch).ctba = (ct_pa.as_u64() & 0xFFFF_FFFF) as u32;
            (*ch).ctbau = (ct_pa.as_u64() >> 32) as u32;
        }
        Ok(())
    }

    fn build_read_command(&self, port: u32, slot: u32, lba: u64, count: u16, buffer_pa: PhysAddr) -> Result<(), &'static str> {
        let (ch, ct_ptr, ct_pa) = self.setup_slot(port, slot)?;
        let bytes = (count as usize) * 512;

        unsafe {
            core::ptr::write_bytes(ch, 0, 1);
            core::ptr::write_bytes(ct_ptr, 0, 1);

            self.fill_h2d_fis(&mut (*ct_ptr).cfis, ATA_CMD_READ_DMA_EXT, lba, count, false);

            (*ct_ptr).prdt[0].dba = (buffer_pa.as_u64() & 0xFFFF_FFFF) as u32;
            (*ct_ptr).prdt[0].dbau = (buffer_pa.as_u64() >> 32) as u32;
            (*ct_ptr).prdt[0].reserved0 = 0;
            (*ct_ptr).prdt[0].dbc = (bytes as u32 - 1) | (1 << 31);

            (*ch).flags = Self::hdr_flags_for(5, false);
            (*ch).prdtl = 1;
            (*ch).prdbc = 0;
            (*ch).ctba = (ct_pa.as_u64() & 0xFFFF_FFFF) as u32;
            (*ch).ctbau = (ct_pa.as_u64() >> 32) as u32;
        }
        Ok(())
    }

    fn build_write_command(&self, port: u32, slot: u32, lba: u64, count: u16, buffer_pa: PhysAddr) -> Result<(), &'static str> {
        let (ch, ct_ptr, ct_pa) = self.setup_slot(port, slot)?;
        let bytes = (count as usize) * 512;

        unsafe {
            core::ptr::write_bytes(ch, 0, 1);
            core::ptr::write_bytes(ct_ptr, 0, 1);

            self.fill_h2d_fis(&mut (*ct_ptr).cfis, ATA_CMD_WRITE_DMA_EXT, lba, count, true);

            (*ct_ptr).prdt[0].dba = (buffer_pa.as_u64() & 0xFFFF_FFFF) as u32;
            (*ct_ptr).prdt[0].dbau = (buffer_pa.as_u64() >> 32) as u32;
            (*ct_ptr).prdt[0].reserved0 = 0;
            (*ct_ptr).prdt[0].dbc = (bytes as u32 - 1) | (1 << 31);

            (*ch).flags = Self::hdr_flags_for(5, true);
            (*ch).prdtl = 1;
            (*ch).prdbc = 0;
            (*ch).ctba = (ct_pa.as_u64() & 0xFFFF_FFFF) as u32;
            (*ch).ctbau = (ct_pa.as_u64() >> 32) as u32;
        }
        Ok(())
    }

    /// Build DSM/TRIM command for 'blocks' × 512B of TRIM descriptors
    fn build_trim_command(&self, port: u32, slot: u32, buffer_pa: PhysAddr, blocks: u16) -> Result<(), &'static str> {
        let (ch, ct_ptr, ct_pa) = self.setup_slot(port, slot)?;
        let bytes = (blocks as usize) * 512;

        unsafe {
            core::ptr::write_bytes(ch, 0, 1);
            core::ptr::write_bytes(ct_ptr, 0, 1);

            // Fill CFIS for DSM/TRIM
            (*ct_ptr).cfis.fill(0);
            (*ct_ptr).cfis[0] = FIS_TYPE_REG_H2D;
            (*ct_ptr).cfis[1] = 1 << 7; // C=1
            (*ct_ptr).cfis[2] = ATA_CMD_DSM;
            (*ct_ptr).cfis[3] = DSM_TRIM; // feature low = TRIM
            (*ct_ptr).cfis[11] = 0;      // feature high
            // LBA fields zero for DSM/TRIM; device register with LBA mode
            (*ct_ptr).cfis[7] = 0x40;
            // Sector count = number of 512B descriptor blocks
            (*ct_ptr).cfis[12] = (blocks & 0xFF) as u8;
            (*ct_ptr).cfis[13] = (blocks >> 8) as u8;

            // PRDT for descriptor buffer
            (*ct_ptr).prdt[0].dba = (buffer_pa.as_u64() & 0xFFFF_FFFF) as u32;
            (*ct_ptr).prdt[0].dbau = (buffer_pa.as_u64() >> 32) as u32;
            (*ct_ptr).prdt[0].reserved0 = 0;
            (*ct_ptr).prdt[0].dbc = (bytes as u32 - 1) | (1 << 31);

            // Header: write (data-out)
            (*ch).flags = Self::hdr_flags_for(5, true);
            (*ch).prdtl = 1;
            (*ch).prdbc = 0;
            (*ch).ctba = (ct_pa.as_u64() & 0xFFFF_FFFF) as u32;
            (*ch).ctbau = (ct_pa.as_u64() >> 32) as u32;
        }
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
        unsafe {
            let data = core::slice::from_raw_parts_mut(buffer as *mut u8, size);
            for (i, byte) in data.iter_mut().enumerate() {
                *byte ^= self.crypto_key[i % 32];
            }
        }
    }

    fn decrypt_buffer(&self, buffer: u64, size: usize) {
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

        unsafe { AHCI_CONTROLLER = Some(controller); }

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
