//! NVMe (Non-Volatile Memory Express) Driver
//!
//! High-performance NVMe SSD driver with MSI-X and DMA support

use crate::drivers::pci::{PciBar, PciDevice};
use alloc::{sync::Arc, vec, vec::Vec};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use spin::{Mutex, RwLock};
use x86_64::{PhysAddr, VirtAddr};

/// NVMe controller registers
const NVME_REG_CAP: u64 = 0x00; // Controller Capabilities
const NVME_REG_VS: u64 = 0x08; // Version
const NVME_REG_INTMS: u64 = 0x0C; // Interrupt Mask Set
const NVME_REG_INTMC: u64 = 0x10; // Interrupt Mask Clear
const NVME_REG_CC: u64 = 0x14; // Controller Configuration
const NVME_REG_CSTS: u64 = 0x1C; // Controller Status
const NVME_REG_NSSR: u64 = 0x20; // NVM Subsystem Reset
const NVME_REG_AQA: u64 = 0x24; // Admin Queue Attributes
const NVME_REG_ASQ: u64 = 0x28; // Admin Submission Queue Base Address
const NVME_REG_ACQ: u64 = 0x30; // Admin Completion Queue Base Address

/// NVMe controller configuration bits
const NVME_CC_ENABLE: u32 = 1 << 0;
const NVME_CC_CSS_NVME: u32 = 0 << 4;
const NVME_CC_MPS_4KB: u32 = 0 << 7;
const NVME_CC_AMS_RR: u32 = 0 << 11;
const NVME_CC_SHN_NORMAL: u32 = 1 << 14;
const NVME_CC_SHN_ABRUPT: u32 = 2 << 14;
const NVME_CC_IOSQES_64: u32 = 6 << 16;
const NVME_CC_IOCQES_16: u32 = 4 << 20;

/// NVMe controller status bits
const NVME_CSTS_RDY: u32 = 1 << 0;
const NVME_CSTS_CFS: u32 = 1 << 1;
const NVME_CSTS_SHST_NORMAL: u32 = 0 << 2;
const NVME_CSTS_SHST_PROGRESS: u32 = 1 << 2;
const NVME_CSTS_SHST_COMPLETE: u32 = 2 << 2;

/// NVMe Admin commands
const NVME_ADMIN_DELETE_SQ: u8 = 0x00;
const NVME_ADMIN_CREATE_SQ: u8 = 0x01;
const NVME_ADMIN_DELETE_CQ: u8 = 0x04;
const NVME_ADMIN_CREATE_CQ: u8 = 0x05;
const NVME_ADMIN_IDENTIFY: u8 = 0x06;
const NVME_ADMIN_ABORT: u8 = 0x08;
const NVME_ADMIN_SET_FEATURES: u8 = 0x09;
const NVME_ADMIN_GET_FEATURES: u8 = 0x0A;
const NVME_ADMIN_ASYNC_EVENT: u8 = 0x0C;
const NVME_ADMIN_NS_MGMT: u8 = 0x0D;
const NVME_ADMIN_ACTIVATE_FW: u8 = 0x10;
const NVME_ADMIN_DOWNLOAD_FW: u8 = 0x11;
const NVME_ADMIN_FORMAT_NVM: u8 = 0x80;
const NVME_ADMIN_SECURITY_SEND: u8 = 0x81;
const NVME_ADMIN_SECURITY_RECV: u8 = 0x82;

/// NVMe I/O commands
const NVME_CMD_FLUSH: u8 = 0x00;
const NVME_CMD_WRITE: u8 = 0x01;
const NVME_CMD_READ: u8 = 0x02;
const NVME_CMD_WRITE_UNCOR: u8 = 0x04;
const NVME_CMD_COMPARE: u8 = 0x05;
const NVME_CMD_WRITE_ZEROS: u8 = 0x08;
const NVME_CMD_DSM: u8 = 0x09;

/// NVMe submission queue entry
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct NvmeCommand {
    pub cdw0: u32,     // Command DWord 0 (opcode, flags, etc.)
    pub nsid: u32,     // Namespace ID
    pub cdw2: u64,     // Reserved
    pub metadata: u64, // Metadata pointer
    pub prp1: u64,     // Physical Region Page 1
    pub prp2: u64,     // Physical Region Page 2
    pub cdw10: u32,    // Command DWord 10
    pub cdw11: u32,    // Command DWord 11
    pub cdw12: u32,    // Command DWord 12
    pub cdw13: u32,    // Command DWord 13
    pub cdw14: u32,    // Command DWord 14
    pub cdw15: u32,    // Command DWord 15
}

/// NVMe completion queue entry
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct NvmeCompletion {
    pub cdw0: u32,    // Command-specific result
    pub cdw1: u32,    // Reserved
    pub sq_head: u16, // Submission queue head pointer
    pub sq_id: u16,   // Submission queue ID
    pub cid: u16,     // Command ID
    pub status: u16,  // Status field
}

/// NVMe namespace information
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct NvmeNamespace {
    pub nsze: u64,        // Namespace Size
    pub ncap: u64,        // Namespace Capacity
    pub nuse: u64,        // Namespace Utilization
    pub nsfeat: u8,       // Namespace Features
    pub nlbaf: u8,        // Number of LBA Formats
    pub flbas: u8,        // Formatted LBA Size
    pub mc: u8,           // Metadata Capabilities
    pub dpc: u8,          // End-to-End Data Protection Capabilities
    pub dps: u8,          // End-to-End Data Protection Type Settings
    pub nmic: u8,         // Namespace Multi-path I/O and NS Sharing Capabilities
    pub rescap: u8,       // Reservation Capabilities
    pub fpi: u8,          // Format Progress Indicator
    pub nawun: u16,       // Namespace Atomic Write Unit Normal
    pub nawupf: u16,      // Namespace Atomic Write Unit Power Fail
    pub nacwu: u16,       // Namespace Atomic Compare & Write Unit
    pub nabsn: u16,       // Namespace Atomic Boundary Size Normal
    pub nabo: u16,        // Namespace Atomic Boundary Offset
    pub nabspf: u16,      // Namespace Atomic Boundary Size Power Fail
    pub noiob: u16,       // Namespace Optimal I/O Boundary
    pub nvmcap: [u8; 16], // NVM Capacity
    pub reserved1: [u8; 40],
    pub nguid: [u8; 16], // Namespace Globally Unique Identifier
    pub eui64: u64,      // IEEE Extended Unique Identifier
    pub lbaf: [u32; 16], // LBA Format Support
    pub reserved2: [u8; 192],
    pub vs: [u8; 3712], // Vendor Specific
}

/// NVMe controller identify data
#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct NvmeController {
    pub vid: u16,      // Vendor ID
    pub ssvid: u16,    // Subsystem Vendor ID
    pub sn: [u8; 20],  // Serial Number
    pub mn: [u8; 40],  // Model Number
    pub fr: [u8; 8],   // Firmware Revision
    pub rab: u8,       // Recommended Arbitration Burst
    pub ieee: [u8; 3], // IEEE OUI Identifier
    pub cmic: u8,      // Controller Multi-Path I/O and NS Sharing Capabilities
    pub mdts: u8,      // Maximum Data Transfer Size
    pub cntlid: u16,   // Controller ID
    pub ver: u32,      // Version
    pub rtd3r: u32,    // RTD3 Resume Latency
    pub rtd3e: u32,    // RTD3 Entry Latency
    pub oaes: u32,     // Optional Asynchronous Events Supported
    pub ctratt: u32,   // Controller Attributes
    pub reserved1: [u8; 156],
    pub oacs: u16,         // Optional Admin Command Support
    pub acl: u8,           // Abort Command Limit
    pub aerl: u8,          // Asynchronous Event Request Limit
    pub frmw: u8,          // Firmware Updates
    pub lpa: u8,           // Log Page Attributes
    pub elpe: u8,          // Error Log Page Entries
    pub npss: u8,          // Number of Power States Support
    pub avscc: u8,         // Admin Vendor Specific Command Configuration
    pub apsta: u8,         // Autonomous Power State Transition Attributes
    pub wctemp: u16,       // Warning Composite Temperature Threshold
    pub cctemp: u16,       // Critical Composite Temperature Threshold
    pub mtfa: u16,         // Maximum Time for Firmware Activation
    pub hmpre: u32,        // Host Memory Buffer Preferred Size
    pub hmmin: u32,        // Host Memory Buffer Minimum Size
    pub tnvmcap: [u8; 16], // Total NVM Capacity
    pub unvmcap: [u8; 16], // Unallocated NVM Capacity
    pub rpmbs: u32,        // Replay Protected Memory Block Support
    pub edstt: u16,        // Extended Device Self-test Time
    pub dsto: u8,          // Device Self-test Options
    pub fwug: u8,          // Firmware Update Granularity
    pub kas: u16,          // Keep Alive Support
    pub hctma: u16,        // Host Controlled Thermal Management Attributes
    pub mntmt: u16,        // Minimum Thermal Management Temperature
    pub mxtmt: u16,        // Maximum Thermal Management Temperature
    pub sanicap: u32,      // Sanitize Capabilities
    pub reserved2: [u8; 180],
    pub sqes: u8,    // Submission Queue Entry Size
    pub cqes: u8,    // Completion Queue Entry Size
    pub maxcmd: u16, // Maximum Outstanding Commands
    pub nn: u32,     // Number of Namespaces
    pub oncs: u16,   // Optional NVM Command Support
    pub fuses: u16,  // Fused Operation Support
    pub fna: u8,     // Format NVM Attributes
    pub vwc: u8,     // Volatile Write Cache
    pub awun: u16,   // Atomic Write Unit Normal
    pub awupf: u16,  // Atomic Write Unit Power Fail
    pub nvscc: u8,   // NVM Vendor Specific Command Configuration
    pub reserved3: u8,
    pub acwu: u16, // Atomic Compare & Write Unit
    pub reserved4: [u8; 2],
    pub sgls: u32, // SGL Support
    pub reserved5: [u8; 228],
    pub subnqn: [u8; 256], // NVM Subsystem NVMe Qualified Name
    pub reserved6: [u8; 768],
    pub nvmeof: [u8; 256], // NVMe over Fabrics
    pub vs: [u8; 1024],    // Vendor Specific
}

/// NVMe queue pair
#[derive(Debug)]
pub struct NvmeQueue {
    pub queue_id: u16,
    pub queue_size: u16,
    pub submission_queue: Vec<NvmeCommand>,
    pub completion_queue: Vec<NvmeCompletion>,
    pub sq_tail: AtomicU32,
    pub cq_head: AtomicU32,
    pub sq_doorbell: VirtAddr,
    pub cq_doorbell: VirtAddr,
    pub phase_tag: AtomicBool,
    pub msix_vector: Option<u16>,
}

impl NvmeQueue {
    /// Create new NVMe queue pair
    pub fn new(
        queue_id: u16,
        queue_size: u16,
        sq_doorbell: VirtAddr,
        cq_doorbell: VirtAddr,
    ) -> Self {
        NvmeQueue {
            queue_id,
            queue_size,
            submission_queue: vec![unsafe { core::mem::zeroed() }; queue_size as usize],
            completion_queue: vec![unsafe { core::mem::zeroed() }; queue_size as usize],
            sq_tail: AtomicU32::new(0),
            cq_head: AtomicU32::new(0),
            sq_doorbell,
            cq_doorbell,
            phase_tag: AtomicBool::new(true),
            msix_vector: None,
        }
    }

    /// Submit command to queue
    pub fn submit_command(&mut self, mut command: NvmeCommand) -> Result<u16, &'static str> {
        let tail = self.sq_tail.load(Ordering::Relaxed);
        let next_tail = (tail + 1) % self.queue_size as u32;

        // Set command ID
        let cid = tail as u16;
        command.cdw0 |= (cid as u32) << 16;

        // Copy command to submission queue
        self.submission_queue[tail as usize] = command;

        // Ring doorbell
        self.sq_tail.store(next_tail, Ordering::Release);
        unsafe {
            core::ptr::write_volatile(self.sq_doorbell.as_mut_ptr::<u32>(), next_tail);
        }

        Ok(cid)
    }

    /// Process completions
    pub fn process_completions(&mut self) -> Vec<NvmeCompletion> {
        let mut completions = Vec::new();
        let mut head = self.cq_head.load(Ordering::Relaxed);
        let current_phase = self.phase_tag.load(Ordering::Relaxed);

        loop {
            let completion = &self.completion_queue[head as usize];
            let phase = (completion.status & 0x01) != 0;

            if phase != current_phase {
                break;
            }

            completions.push(*completion);
            head = (head + 1) % self.queue_size as u32;

            if head == 0 {
                self.phase_tag.store(!current_phase, Ordering::Relaxed);
            }
        }

        if !completions.is_empty() {
            self.cq_head.store(head, Ordering::Release);

            // Ring completion doorbell
            unsafe {
                core::ptr::write_volatile(self.cq_doorbell.as_mut_ptr::<u32>(), head);
            }
        }

        completions
    }
}

/// NVMe I/O request
#[derive(Debug)]
pub struct NvmeRequest {
    pub nsid: u32,
    pub opcode: u8,
    pub lba: u64,
    pub block_count: u32,
    pub buffer: VirtAddr,
    pub buffer_size: usize,
    pub completion_callback: Option<fn(Result<(), &'static str>)>,
}

/// NVMe driver
pub struct NvmeDriver {
    pub controller_bar: PhysAddr,
    pub controller_size: usize,
    pub admin_queue: Mutex<NvmeQueue>,
    pub io_queues: RwLock<Vec<Arc<Mutex<NvmeQueue>>>>,
    pub controller_info: RwLock<Option<NvmeController>>,
    pub namespaces: RwLock<Vec<NvmeNamespace>>,
    pub max_transfer_size: AtomicU32,
    pub queue_count: AtomicU32,
    pub namespace_count: AtomicU32,
    pub ready: AtomicBool,

    // Performance statistics
    pub read_ops: AtomicU64,
    pub write_ops: AtomicU64,
    pub bytes_read: AtomicU64,
    pub bytes_written: AtomicU64,
    pub avg_latency_ns: AtomicU64,
}

impl NvmeDriver {
    /// Create new NVMe driver
    pub fn new(pci_device: &PciDevice) -> Result<Self, &'static str> {
        // Get BAR 0 (controller registers)
        let controller_bar = match pci_device.bars[0] {
            Some(PciBar::Memory { address, size, .. }) => (address, size),
            _ => return Err("NVMe controller BAR 0 must be memory mapped"),
        };

        // Enable bus mastering and memory access
        pci_device.enable_bus_mastering();

        let driver = NvmeDriver {
            controller_bar: controller_bar.0,
            controller_size: controller_bar.1,
            admin_queue: Mutex::new(NvmeQueue::new(0, 64, VirtAddr::new(0), VirtAddr::new(0))),
            io_queues: RwLock::new(Vec::new()),
            controller_info: RwLock::new(None),
            namespaces: RwLock::new(Vec::new()),
            max_transfer_size: AtomicU32::new(65536), // 64KB default
            queue_count: AtomicU32::new(1),           // Admin queue
            namespace_count: AtomicU32::new(0),
            ready: AtomicBool::new(false),
            read_ops: AtomicU64::new(0),
            write_ops: AtomicU64::new(0),
            bytes_read: AtomicU64::new(0),
            bytes_written: AtomicU64::new(0),
            avg_latency_ns: AtomicU64::new(0),
        };

        Ok(driver)
    }

    /// Initialize NVMe controller
    pub fn initialize(&mut self, pci_device: &PciDevice) -> Result<(), &'static str> {
        // Reset controller
        self.reset_controller()?;

        // Wait for controller to be ready
        self.wait_for_ready(5000)?; // 5 second timeout

        // Read controller capabilities
        let cap = self.read_controller_reg(NVME_REG_CAP);
        let doorbell_stride = ((cap >> 32) & 0xF) as u32;
        let max_queue_entries = ((cap & 0xFFFF) + 1) as u16;

        // Setup admin queues
        self.setup_admin_queues(max_queue_entries, doorbell_stride)?;

        // Enable controller
        self.enable_controller()?;

        // Wait for controller to be ready
        self.wait_for_ready(5000)?;

        // Setup MSI-X if available
        if pci_device.msix_capability.is_some() {
            self.setup_msix_interrupts(pci_device)?;
        }

        // Identify controller
        self.identify_controller()?;

        // Identify namespaces
        self.identify_namespaces()?;

        // Create I/O queues
        self.create_io_queues(4)?; // 4 I/O queue pairs

        self.ready.store(true, Ordering::Relaxed);
        Ok(())
    }

    /// Reset NVMe controller
    fn reset_controller(&self) -> Result<(), &'static str> {
        // Disable controller
        self.write_controller_reg(NVME_REG_CC, 0);

        // Wait for controller to be disabled
        for _ in 0..1000 {
            let csts = self.read_controller_reg(NVME_REG_CSTS);
            if (csts & (NVME_CSTS_RDY as u64)) == 0 {
                return Ok(());
            }
            // Sleep 1ms
            for _ in 0..1000000 {
                unsafe {
                    core::arch::asm!("pause");
                }
            }
        }

        Err("Controller reset timeout")
    }

    /// Wait for controller ready
    fn wait_for_ready(&self, timeout_ms: u32) -> Result<(), &'static str> {
        for _ in 0..timeout_ms {
            let csts = self.read_controller_reg(NVME_REG_CSTS);
            if (csts & (NVME_CSTS_RDY as u64)) != 0 {
                return Ok(());
            }
            if (csts & (NVME_CSTS_CFS as u64)) != 0 {
                return Err("Controller fatal error");
            }
            // Sleep 1ms
            for _ in 0..1000000 {
                unsafe {
                    core::arch::asm!("pause");
                }
            }
        }

        Err("Controller ready timeout")
    }

    /// Setup admin queues
    fn setup_admin_queues(
        &mut self,
        max_entries: u16,
        doorbell_stride: u32,
    ) -> Result<(), &'static str> {
        let queue_size = 64u16.min(max_entries);

        // Allocate admin queue memory
        let sq_pages = ((queue_size as usize * 64) + 4095) / 4096;
        let cq_pages = ((queue_size as usize * 16) + 4095) / 4096;

        let mut sq_frames = Vec::new();
        let mut cq_frames = Vec::new();

        for _ in 0..sq_pages {
            if let Some(frame) = crate::memory::page_allocator::allocate_frame() {
                sq_frames.push(frame);
            } else {
                return Err("Failed to allocate admin SQ memory");
            }
        }

        for _ in 0..cq_pages {
            if let Some(frame) = crate::memory::page_allocator::allocate_frame() {
                cq_frames.push(frame);
            } else {
                return Err("Failed to allocate admin CQ memory");
            }
        }

        let sq_addr = sq_frames[0].start_address();
        let cq_addr = cq_frames[0].start_address();

        // Calculate doorbell addresses
        let doorbell_base = self.controller_bar.as_u64() + 0x1000;
        let sq_doorbell = VirtAddr::new(doorbell_base);
        let cq_doorbell = VirtAddr::new(doorbell_base + (1 * doorbell_stride * 4) as u64);

        // Setup admin queue
        let mut admin_queue = self.admin_queue.lock();
        *admin_queue = NvmeQueue::new(0, queue_size, sq_doorbell, cq_doorbell);

        // Configure admin queue attributes
        let aqa = ((queue_size as u32 - 1) << 16) | (queue_size as u32 - 1);
        self.write_controller_reg(NVME_REG_AQA, aqa as u64);
        self.write_controller_reg(NVME_REG_ASQ, sq_addr.as_u64());
        self.write_controller_reg(NVME_REG_ACQ, cq_addr.as_u64());

        Ok(())
    }

    /// Enable NVMe controller
    fn enable_controller(&self) -> Result<(), &'static str> {
        let cc = NVME_CC_ENABLE
            | NVME_CC_CSS_NVME
            | NVME_CC_MPS_4KB
            | NVME_CC_AMS_RR
            | NVME_CC_IOSQES_64
            | NVME_CC_IOCQES_16;

        self.write_controller_reg(NVME_REG_CC, cc as u64);
        Ok(())
    }

    /// Setup MSI-X interrupts
    fn setup_msix_interrupts(&self, pci_device: &PciDevice) -> Result<(), &'static str> {
        pci_device.enable_msix()?;

        // Configure MSI-X vector for admin queue
        pci_device.configure_msix_vector(0, 0xFEE00000, 0x4000)?; // CPU 0, vector 0x40

        Ok(())
    }

    /// Identify controller
    fn identify_controller(&self) -> Result<(), &'static str> {
        // Allocate buffer for controller identify data
        let buffer_frame = crate::memory::page_allocator::allocate_frame()
            .ok_or("Failed to allocate identify buffer")?;

        let command = NvmeCommand {
            cdw0: NVME_ADMIN_IDENTIFY as u32,
            nsid: 0,
            cdw2: 0,
            metadata: 0,
            prp1: buffer_frame.start_address().as_u64(),
            prp2: 0,
            cdw10: 1, // Controller identify
            cdw11: 0,
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        };

        let mut admin_queue = self.admin_queue.lock();
        let cid = admin_queue.submit_command(command)?;

        // Wait for completion
        for _ in 0..1000 {
            let completions = admin_queue.process_completions();
            for completion in completions {
                if completion.cid == cid {
                    if completion.status >> 1 == 0 {
                        // Success - read controller data
                        unsafe {
                            let controller_data = core::ptr::read(
                                buffer_frame.start_address().as_u64() as *const NvmeController,
                            );
                            let mut info = self.controller_info.write();
                            *info = Some(controller_data);

                            self.namespace_count.store(controller_data.nn, Ordering::Relaxed);

                            // Calculate max transfer size
                            let mdts = controller_data.mdts;
                            if mdts > 0 {
                                let max_size = 4096u32 << mdts;
                                self.max_transfer_size.store(max_size, Ordering::Relaxed);
                            }
                        }
                        return Ok(());
                    } else {
                        return Err("Controller identify failed");
                    }
                }
            }
            // Sleep 1ms
            for _ in 0..1000000 {
                unsafe {
                    core::arch::asm!("pause");
                }
            }
        }

        Err("Controller identify timeout")
    }

    /// Identify namespaces
    fn identify_namespaces(&self) -> Result<(), &'static str> {
        let namespace_count = self.namespace_count.load(Ordering::Relaxed);
        let mut namespaces = self.namespaces.write();

        for nsid in 1..=namespace_count {
            // Allocate buffer for namespace identify data
            let buffer_frame = crate::memory::page_allocator::allocate_frame()
                .ok_or("Failed to allocate identify buffer")?;

            let command = NvmeCommand {
                cdw0: NVME_ADMIN_IDENTIFY as u32,
                nsid,
                cdw2: 0,
                metadata: 0,
                prp1: buffer_frame.start_address().as_u64(),
                prp2: 0,
                cdw10: 0, // Namespace identify
                cdw11: 0,
                cdw12: 0,
                cdw13: 0,
                cdw14: 0,
                cdw15: 0,
            };

            let mut admin_queue = self.admin_queue.lock();
            let cid = admin_queue.submit_command(command)?;

            // Wait for completion
            for _ in 0..1000 {
                let completions = admin_queue.process_completions();
                for completion in completions {
                    if completion.cid == cid {
                        if completion.status >> 1 == 0 {
                            unsafe {
                                let namespace_data =
                                    core::ptr::read(buffer_frame.start_address().as_u64()
                                        as *const NvmeNamespace);
                                namespaces.push(namespace_data);
                            }
                            break;
                        }
                    }
                }
                // Sleep 1ms
                for _ in 0..1000000 {
                    unsafe {
                        core::arch::asm!("pause");
                    }
                }
            }
        }

        Ok(())
    }

    /// Create I/O queues
    fn create_io_queues(&self, queue_pairs: u32) -> Result<(), &'static str> {
        let mut io_queues = self.io_queues.write();

        for qid in 1..=queue_pairs {
            // Create completion queue first
            self.create_completion_queue(qid as u16)?;

            // Then create submission queue
            self.create_submission_queue(qid as u16)?;

            // Add to I/O queues list
            let sq_doorbell =
                VirtAddr::new(self.controller_bar.as_u64() + 0x1000 + (qid * 8) as u64);
            let cq_doorbell =
                VirtAddr::new(self.controller_bar.as_u64() + 0x1000 + (qid * 8 + 4) as u64);

            let queue =
                Arc::new(Mutex::new(NvmeQueue::new(qid as u16, 256, sq_doorbell, cq_doorbell)));
            io_queues.push(queue);
        }

        self.queue_count.store(queue_pairs + 1, Ordering::Relaxed);
        Ok(())
    }

    /// Create completion queue
    fn create_completion_queue(&self, qid: u16) -> Result<(), &'static str> {
        let buffer_frame = crate::memory::page_allocator::allocate_frame()
            .ok_or("Failed to allocate CQ memory")?;

        let command = NvmeCommand {
            cdw0: NVME_ADMIN_CREATE_CQ as u32,
            nsid: 0,
            cdw2: 0,
            metadata: 0,
            prp1: buffer_frame.start_address().as_u64(),
            prp2: 0,
            cdw10: ((255u32) << 16) | qid as u32, // Queue size and ID
            cdw11: 0x01,                          // Physically contiguous, interrupts enabled
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        };

        let mut admin_queue = self.admin_queue.lock();
        let _cid = admin_queue.submit_command(command)?;

        // Wait for completion (simplified)
        for _ in 0..1000 {
            let completions = admin_queue.process_completions();
            if !completions.is_empty() {
                return Ok(());
            }
            // Sleep 1ms
            for _ in 0..1000000 {
                unsafe {
                    core::arch::asm!("pause");
                }
            }
        }

        Err("Create CQ timeout")
    }

    /// Create submission queue
    fn create_submission_queue(&self, qid: u16) -> Result<(), &'static str> {
        let buffer_frame = crate::memory::page_allocator::allocate_frame()
            .ok_or("Failed to allocate SQ memory")?;

        let command = NvmeCommand {
            cdw0: NVME_ADMIN_CREATE_SQ as u32,
            nsid: 0,
            cdw2: 0,
            metadata: 0,
            prp1: buffer_frame.start_address().as_u64(),
            prp2: 0,
            cdw10: ((255u32) << 16) | qid as u32, // Queue size and ID
            cdw11: (qid as u32) << 16 | 0x01,     // CQ ID and physically contiguous
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        };

        let mut admin_queue = self.admin_queue.lock();
        let _cid = admin_queue.submit_command(command)?;

        // Wait for completion (simplified)
        for _ in 0..1000 {
            let completions = admin_queue.process_completions();
            if !completions.is_empty() {
                return Ok(());
            }
            // Sleep 1ms
            for _ in 0..1000000 {
                unsafe {
                    core::arch::asm!("pause");
                }
            }
        }

        Err("Create SQ timeout")
    }

    /// Read from NVMe device
    pub fn read(
        &self,
        nsid: u32,
        lba: u64,
        block_count: u32,
        buffer: VirtAddr,
    ) -> Result<(), &'static str> {
        if !self.ready.load(Ordering::Relaxed) {
            return Err("NVMe controller not ready");
        }

        let command = NvmeCommand {
            cdw0: NVME_CMD_READ as u32,
            nsid,
            cdw2: 0,
            metadata: 0,
            prp1: buffer.as_u64(), // Simplified - would need proper PRP setup
            prp2: 0,
            cdw10: (lba & 0xFFFFFFFF) as u32,
            cdw11: (lba >> 32) as u32,
            cdw12: (block_count - 1) as u32,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        };

        // Select I/O queue (round-robin for simplicity)
        let io_queues = self.io_queues.read();
        if io_queues.is_empty() {
            return Err("No I/O queues available");
        }

        let queue_index = (lba % io_queues.len() as u64) as usize;
        let mut queue = io_queues[queue_index].lock();

        let _cid = queue.submit_command(command)?;

        // Update statistics
        self.read_ops.fetch_add(1, Ordering::Relaxed);
        self.bytes_read.fetch_add((block_count * 512) as u64, Ordering::Relaxed);

        Ok(())
    }

    /// Write to NVMe device
    pub fn write(
        &self,
        nsid: u32,
        lba: u64,
        block_count: u32,
        buffer: VirtAddr,
    ) -> Result<(), &'static str> {
        if !self.ready.load(Ordering::Relaxed) {
            return Err("NVMe controller not ready");
        }

        let command = NvmeCommand {
            cdw0: NVME_CMD_WRITE as u32,
            nsid,
            cdw2: 0,
            metadata: 0,
            prp1: buffer.as_u64(),
            prp2: 0,
            cdw10: (lba & 0xFFFFFFFF) as u32,
            cdw11: (lba >> 32) as u32,
            cdw12: (block_count - 1) as u32,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        };

        // Select I/O queue
        let io_queues = self.io_queues.read();
        if io_queues.is_empty() {
            return Err("No I/O queues available");
        }

        let queue_index = (lba % io_queues.len() as u64) as usize;
        let mut queue = io_queues[queue_index].lock();

        let _cid = queue.submit_command(command)?;

        // Update statistics
        self.write_ops.fetch_add(1, Ordering::Relaxed);
        self.bytes_written.fetch_add((block_count * 512) as u64, Ordering::Relaxed);

        Ok(())
    }

    /// Read controller register
    fn read_controller_reg(&self, offset: u64) -> u64 {
        unsafe {
            let reg_addr = (self.controller_bar.as_u64() + offset) as *const u64;
            core::ptr::read_volatile(reg_addr)
        }
    }

    /// Write controller register
    fn write_controller_reg(&self, offset: u64, value: u64) {
        unsafe {
            let reg_addr = (self.controller_bar.as_u64() + offset) as *mut u64;
            core::ptr::write_volatile(reg_addr, value);
        }
    }

    /// Get driver statistics
    pub fn get_stats(&self) -> NvmeStats {
        NvmeStats {
            commands_completed: self.read_ops.load(Ordering::Relaxed)
                + self.write_ops.load(Ordering::Relaxed),
            bytes_read: self.bytes_read.load(Ordering::Relaxed),
            bytes_written: self.bytes_written.load(Ordering::Relaxed),
            errors: 0, // Would be tracked in actual implementation
            namespaces: self.namespace_count.load(Ordering::Relaxed),
        }
    }
}

/// NVMe driver statistics
#[derive(Debug, Clone)]
pub struct NvmeStats {
    pub commands_completed: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub errors: u64,
    pub namespaces: u32,
}

impl Default for NvmeStats {
    fn default() -> Self {
        Self { commands_completed: 0, bytes_read: 0, bytes_written: 0, errors: 0, namespaces: 0 }
    }
}

/// Global NVMe controller instance
static mut NVME_CONTROLLER: Option<NvmeDriver> = None;

/// Initialize NVMe subsystem
pub fn init_nvme() -> Result<(), &'static str> {
    // Find NVMe controller via PCI
    if let Some(nvme_device) = crate::drivers::pci::find_device_by_class(0x01, 0x08) {
        let mut driver = NvmeDriver::new(&nvme_device)?;
        driver.initialize(&nvme_device)?;

        unsafe {
            NVME_CONTROLLER = Some(driver);
        }

        crate::log::logger::log_critical("NVMe subsystem initialized");
        Ok(())
    } else {
        Err("No NVMe controller found")
    }
}

/// Get NVMe controller
pub fn get_controller() -> Option<&'static NvmeDriver> {
    unsafe { NVME_CONTROLLER.as_ref() }
}

/// Get mutable NVMe controller
pub fn get_controller_mut() -> Option<&'static mut NvmeDriver> {
    unsafe { NVME_CONTROLLER.as_mut() }
}
