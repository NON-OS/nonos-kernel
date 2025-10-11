//! NVMe (Non-Volatile Memory Express) Driver
//! NOTE:
//! - This driver uses a single I/O queue pair (qid=1) for simplicity and stability.
//! - Add more queues and CPU affinity later for scale.
//! - This module relies on crate::memory::dma::alloc_dma_coherent and crate::memory::mmio::*.

use core::{mem, ptr};
use core::sync::atomic::{AtomicU64, Ordering};
use alloc::vec::Vec;
use spin::Mutex;
use x86_64::{PhysAddr, VirtAddr};

use crate::memory::dma::alloc_dma_coherent;
use crate::memory::mmio::{mmio_r32, mmio_r64, mmio_w32, mmio_w64};
use crate::drivers::pci::PciDevice;

// NVMe PCI class codes: Base 0x01 (Mass Storage), Subclass 0x08 (NVM), ProgIF 0x02 (NVMe)
const NVME_CLASS: u8 = 0x01;
const NVME_SUBCLASS: u8 = 0x08;
const NVME_PROGIF: u8 = 0x02;

// BAR0 is MMIO for NVMe per spec (most devices)
const NVME_BAR_INDEX: u8 = 0;

// MMIO register offsets
const REG_CAP: usize = 0x0000; // Controller Capabilities
const REG_VS: usize = 0x0008;  // Version
const REG_INTMS: usize = 0x000C; // Interrupt Mask Set
const REG_INTMC: usize = 0x0010; // Interrupt Mask Clear
const REG_CC: usize = 0x0014;   // Controller Configuration
const REG_CSTS: usize = 0x001C; // Controller Status
const REG_AQA: usize = 0x0024;  // Admin Queue Attributes
const REG_ASQ: usize = 0x0028;  // Admin Submission Queue Base Addr
const REG_ACQ: usize = 0x0030;  // Admin Completion Queue Base Addr
const REG_DBS: usize = 0x1000;  // Doorbell Stride base

// CC bits
const CC_ENABLE: u32 = 1;
const CC_CSS_NVM: u32 = 0 << 4; // NVM Command Set
const CC_MPS_SHIFT: u32 = 7;    // MPS in CC = log2(MPS) - 12
const CC_AMS_SHIFT: u32 = 11;   // Arbitration mechanism
const CC_SHN_SHIFT: u32 = 14;   // Shutdown notification

// CSTS bits
const CSTS_RDY: u32 = 1;
const CSTS_CFS: u32 = 1 << 1;

// Admin Opcodes
const OPC_IDENTIFY: u8 = 0x06;
const OPC_CREATE_IO_CQ: u8 = 0x05;
const OPC_CREATE_IO_SQ: u8 = 0x01;

// NVM I/O Opcodes
const OPC_READ: u8 = 0x02;
const OPC_WRITE: u8 = 0x01;

// Identify CNS values
const CNS_IDENTIFY_NAMESPACE: u32 = 0x00;
const CNS_IDENTIFY_CONTROLLER: u32 = 0x01;
const CNS_ACTIVE_NS_LIST: u32 = 0x02;

// PRP constraints
const PAGE_SIZE: usize = 4096;

// Queue sizing
const ADMIN_Q_ENTRIES: u16 = 32; // Admin queue depth
const IO_Q_ENTRIES: u16 = 256;   // IO queue depth (power-of-two recommended)

// Doorbell helper (NVMe: 2 doorbells per Q: SQ tail, CQ head; each is 4 bytes)
#[inline(always)]
fn db_offset_cq(db_stride: u32, qid: u16) -> usize {
    REG_DBS + (2 * qid as usize + 1) * (4 << db_stride)
}
#[inline(always)]
fn db_offset_sq(db_stride: u32, qid: u16) -> usize {
    REG_DBS + (2 * qid as usize + 0) * (4 << db_stride)
}

#[repr(C, align(64))]
#[derive(Clone, Copy)]
struct NvmeSubmission {
    // DW0
    opcode: u8,
    flags: u8,
    cid: u16,

    // DW1
    nsid: u32,

    // DW2-3 (resvd or metadata ptr low)
    rsvd2: u64,

    // DW4-5 PRP1
    prp1: u64,

    // DW6-7 PRP2 or SGL
    prp2: u64,

    // DW8-15 Command-specific
    cdw10: u32,
    cdw11: u32,
    cdw12: u32,
    cdw13: u32,
    cdw14: u32,
    cdw15: u32,
}

impl Default for NvmeSubmission {
    fn default() -> Self {
        NvmeSubmission {
            opcode: 0,
            flags: 0,
            cid: 0,
            nsid: 0,
            rsvd2: 0,
            prp1: 0,
            prp2: 0,
            cdw10: 0,
            cdw11: 0,
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        }
    }
}

#[repr(C, align(16))]
#[derive(Clone, Copy)]
struct NvmeCompletion {
    // DW0-1
    result: u32,
    rsvd: u32,
    // DW2
    sq_head: u16,
    sq_id: u16,
    // DW3
    cid: u16,
    status: u16, // bit0: phase tag
}

struct DmaRegion {
    va: VirtAddr,
    pa: PhysAddr,
    size: usize,
}

impl DmaRegion {
    fn new(size: usize) -> Result<Self, &'static str> {
        let size_rounded = ((size + PAGE_SIZE - 1) / PAGE_SIZE) * PAGE_SIZE;
        let (va, pa) = alloc_dma_coherent(size_rounded)?;
        unsafe { ptr::write_bytes(va.as_mut_ptr::<u8>(), 0, size_rounded); }
        Ok(Self { va, pa, size: size_rounded })
    }
    #[inline] fn phys(&self) -> u64 { self.pa.as_u64() }
    #[inline] fn as_mut_ptr<T>(&self) -> *mut T { self.va.as_mut_ptr::<T>() }
}

struct Queue {
    // Submission
    sq: DmaRegion,
    sq_entries: *mut NvmeSubmission,
    sq_tail: u16,

    // Completion
    cq: DmaRegion,
    cq_entries: *mut NvmeCompletion,
    cq_head: u16,
    cq_phase: u16,

    qid: u16,
    qsize: u16,
}

impl Queue {
    fn new(qid: u16, qsize: u16) -> Result<Self, &'static str> {
        let sq = DmaRegion::new(qsize as usize * mem::size_of::<NvmeSubmission>())?;
        let cq = DmaRegion::new(qsize as usize * mem::size_of::<NvmeCompletion>())?;
        Ok(Self {
            sq_entries: sq.as_mut_ptr::<NvmeSubmission>(),
            cq_entries: cq.as_mut_ptr::<NvmeCompletion>(),
            sq,
            cq,
            sq_tail: 0,
            cq_head: 0,
            cq_phase: 1,
            qid,
            qsize,
        })
    }

    #[inline]
    fn sq_next_index(&self) -> usize {
        self.sq_tail as usize % self.qsize as usize
    }

    #[inline]
    fn cq_next_index(&self) -> usize {
        self.cq_head as usize % self.qsize as usize
    }
}

pub struct NvmeNamespace {
    pub id: u32,
    pub lba_size: u32,
    pub capacity_lba: u64,
}

pub struct NvmeController {
    // PCI and MMIO
    pub pci: PciDevice,
    pub mmio_base: usize,
    db_stride: u32,

    // Admin queue (qid=0)
    admin: Mutex<Queue>,

    // I/O queue (qid=1)
    io: Mutex<Option<Queue>>,

    // Identified info
    pub ns: Option<NvmeNamespace>,

    // Stats
    pub stats: NvmeStats,
}

#[derive(Default, Clone)]
pub struct NvmeStats {
    pub commands_completed: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    pub errors: u64,
    pub namespaces: u32,
}

static NVME_CONTROLLER: spin::Once<&'static Mutex<NvmeController>> = spin::Once::new();

impl NvmeController {
    pub fn init(pci: PciDevice) -> Result<&'static Mutex<Self>, &'static str> {
        // BAR0 MMIO base
        let bar = pci.get_bar(NVME_BAR_INDEX as usize)?;
        let mmio_base = match bar {
            crate::drivers::pci::PciBar::Memory { address, .. } => address.as_u64() as usize,
            _ => return Err("NVMe BAR0 is not MMIO"),
        };

        // Read CAP for MPSMIN, DSTRD
        let cap = unsafe { mmio_r64(mmio_base + REG_CAP) };
        let dstrd = ((cap >> 32) & 0xF) as u32; // doorbell stride power-of-two: register stride = 4 << dstrd
        let mpsmin = ((cap >> 48) & 0xF) as u32; // minimum memory page size = 2^(12 + mpsmin)

        // Disable controller if enabled
        let cc = unsafe { mmio_r32(mmio_base + REG_CC) };
        if (cc & CC_ENABLE) != 0 {
            // Clear CC.EN
            unsafe { mmio_w32(mmio_base + REG_CC, cc & !CC_ENABLE); }
            if !Self::wait(|csts| (csts & CSTS_RDY) == 0, mmio_base, 1_000_000) {
                return Err("NVMe: timeout waiting for CC.EN=0 -> CSTS.RDY=0");
            }
        }

        // Unmask interrupts (we’ll set MSI-X in PCI path)
        unsafe {
            mmio_w32(mmio_base + REG_INTMS, 0);
            mmio_w32(mmio_base + REG_INTMC, 0xFFFF_FFFF);
            mmio_w32(mmio_base + REG_INTMC, 0); // clear any masks
        }

        // Create admin queue
        let admin_q = Queue::new(0, ADMIN_Q_ENTRIES)?;

        // Program AQA, ASQ, ACQ
        unsafe {
            // Admin Queue Attributes: AQA (CQ/SQ size - 1)
            let aqa = ((ADMIN_Q_ENTRIES as u32 - 1) << 16) | ((ADMIN_Q_ENTRIES as u32 - 1) << 0);
            mmio_w32(mmio_base + REG_AQA, aqa);

            // Base addresses must be 4K aligned
            mmio_w64(mmio_base + REG_ASQ, admin_q.sq.phys());
            mmio_w64(mmio_base + REG_ACQ, admin_q.cq.phys());
        }

        // Enable controller: set CC with MPS to PAGE_SIZE, CSS to NVM
        let mut cc_new: u32 = 0;
        // MPS: log2(PAGE_SIZE) - 12
        let mut mps = (PAGE_SIZE.trailing_zeros() - 12) as u32;
        // Ensure MPS >= MPSMIN
        if mps < mpsmin { mps = mpsmin; }
        cc_new |= (mps & 0xF) << CC_MPS_SHIFT;
        cc_new |= CC_CSS_NVM; // CSS=NVM
        cc_new |= CC_ENABLE;

        unsafe { mmio_w32(mmio_base + REG_CC, cc_new); }
        if !Self::wait(|csts| (csts & CSTS_RDY) != 0, mmio_base, 1_000_000) {
            return Err("NVMe: timeout waiting for CSTS.RDY=1");
        }

        // Bring up identify (needs admin queue working)
        let ctrl = NvmeController {
            pci,
            mmio_base,
            db_stride: dstrd,
            admin: Mutex::new(admin_q),
            io: Mutex::new(None),
            ns: None,
            stats: NvmeStats::default(),
        };

        let ctrl_mutex = Box::leak(Box::new(Mutex::new(ctrl)));
        let me = ctrl_mutex;

        // Optional: configure MSI-X 
        {
            let mut g = me.lock();
            let _ = g.pci.configure_msix(crate::interrupts::allocate_vector()?);
        }

        // Identify controller and discover namespace 1 (common minimal case)
        {
            let mut g = me.lock();
            g.identify_controller()?;
            if let Some(ns) = g.identify_first_namespace()? {
                g.ns = Some(ns);
                g.create_io_queues(IO_Q_ENTRIES)?;
            } else {
                return Err("NVMe: no active namespaces");
            }
        }

        NVME_CONTROLLER.call_once(|| me);
        Ok(me)
    }

    fn wait<F: Fn(u32) -> bool>(pred: F, base: usize, mut spins: u32) -> bool {
        while spins > 0 {
            let csts = unsafe { mmio_r32(base + REG_CSTS) };
            if pred(csts) { return true; }
            spins -= 1;
        }
        false
    }

    fn ring_sq_tail(&self, qid: u16, tail: u16) {
        unsafe { mmio_w32(self.mmio_base + db_offset_sq(self.db_stride, qid), tail as u32); }
    }

    fn ring_cq_head(&self, qid: u16, head: u16) {
        unsafe { mmio_w32(self.mmio_base + db_offset_cq(self.db_stride, qid), head as u32); }
    }

    fn admin_submit_sync(&self, mut cmd: NvmeSubmission, data_len: usize, data_pa: Option<PhysAddr>) -> Result<NvmeCompletion, &'static str> {
        let mut q = self.admin.lock();

        // Assign CID = SQ tail
        cmd.cid = q.sq_tail;

        // Wire PRP if needed
        if data_len > 0 {
            let (prp1, prp2) = self.build_prps(data_len, data_pa.unwrap())?;
            cmd.prp1 = prp1;
            cmd.prp2 = prp2;
        }

        // Write to SQ
        let idx = q.sq_next_index();
        unsafe { ptr::write_volatile(q.sq_entries.add(idx), cmd); }

        // Update SQ tail
        q.sq_tail = q.sq_tail.wrapping_add(1);
        self.ring_sq_tail(0, q.sq_tail);

        // Poll CQ
        self.poll_cq(&mut q, 0, cmd.cid)
    }

    fn poll_cq(&self, q: &mut Queue, qid: u16, cid_expected: u16) -> Result<NvmeCompletion, &'static str> {
        let mut spins = 2_000_000u32;
        loop {
            let idx = q.cq_next_index();
            let cqe = unsafe { ptr::read_volatile(q.cq_entries.add(idx)) };
            let phase = (cqe.status & 1) as u16;

            if phase == q.cq_phase {
                // Completion entry is new
                // Advance head and possibly flip phase
                q.cq_head = q.cq_head.wrapping_add(1);
                if (q.cq_head % q.qsize) == 0 {
                    q.cq_phase ^= 1;
                }
                self.ring_cq_head(qid, q.cq_head);

                // Validate CID
                if cqe.cid != cid_expected {
                    // Not the one we waited for; in single-threaded admin it should match
                }

                // Check status code
                let sc = (cqe.status >> 1) & 0x7FF;
                if sc != 0 {
                    return Err("NVMe: Admin command failed (SC != 0)");
                }
                return Ok(cqe);
            }

            if spins == 0 {
                return Err("NVMe: CQ poll timeout");
            }
            spins -= 1;
        }
    }

    fn identify_controller(&self) -> Result<(), &'static str> {
        // Identify Controller -> 4096 bytes buffer
        let id_bytes = 4096usize;
        let (buf_va, buf_pa) = alloc_dma_coherent(id_bytes)?;
        unsafe { ptr::write_bytes(buf_va.as_mut_ptr::<u8>(), 0, id_bytes); }

        let mut cmd = NvmeSubmission::default();
        cmd.opcode = OPC_IDENTIFY;
        cmd.nsid = 0;
        cmd.cdw10 = CNS_IDENTIFY_CONTROLLER;

        let _cpl = self.admin_submit_sync(cmd, id_bytes, Some(buf_pa))?;
        // Could parse NN (number of namespaces) from identify data DW 516 (offset 0x004); identify NS 1 directly.
        Ok(())
    }

    fn identify_first_namespace(&self) -> Result<Option<NvmeNamespace>, &'static str> {
        // Identify active NS list (CNS=0x02) returns 4096 bytes of NSIDs
        let list_bytes = 4096usize;
        let (list_va, list_pa) = alloc_dma_coherent(list_bytes)?;
        unsafe { ptr::write_bytes(list_va.as_mut_ptr::<u8>(), 0, list_bytes); }

        let mut cmd = NvmeSubmission::default();
        cmd.opcode = OPC_IDENTIFY;
        cmd.nsid = 0;
        cmd.cdw10 = CNS_ACTIVE_NS_LIST;

        let _ = self.admin_submit_sync(cmd, list_bytes, Some(list_pa))?;

        // Parse first NSID
        let nsids = unsafe { core::slice::from_raw_parts(list_va.as_ptr::<u32>(), list_bytes / 4) };
        let first_nsid = nsids.iter().cloned().find(|&x| x != 0).unwrap_or(0);
        if first_nsid == 0 {
            return Ok(None);
        }

        // Identify Namespace (CNS=0x00)
        let (ns_va, ns_pa) = alloc_dma_coherent(4096)?;
        unsafe { ptr::write_bytes(ns_va.as_mut_ptr::<u8>(), 0, 4096); }

        let mut cmd_ns = NvmeSubmission::default();
        cmd_ns.opcode = OPC_IDENTIFY;
        cmd_ns.nsid = first_nsid;
        cmd_ns.cdw10 = CNS_IDENTIFY_NAMESPACE;

        let _ = self.admin_submit_sync(cmd_ns, 4096, Some(ns_pa))?;

        // Parse LBADS and NSZE
        let ns_data = unsafe { core::slice::from_raw_parts(ns_va.as_ptr::<u8>(), 4096) };
        // dword 1 (FLBAS) at offset 0x004, but LBADS comes from LBAF[flbas&0xF].LBADS
        let flbas = u32::from_le_bytes([ns_data[4], ns_data[5], ns_data[6], ns_data[7]]) & 0xF;
        // LBAF array starts at byte 0x3C; each LBAF is 4 bytes; LBADS is lower 4 bits of byte 0 of each LBAF
        let lbaf_off = 0x3C + (flbas as usize * 4);
        let lbads = ns_data[lbaf_off] & 0x0F;
        let lba_size = 1u32 << lbads;

        // NSZE at offset 0x028 (8 bytes)
        let nsze = u64::from_le_bytes([
            ns_data[0x28], ns_data[0x29], ns_data[0x2A], ns_data[0x2B],
            ns_data[0x2C], ns_data[0x2D], ns_data[0x2E], ns_data[0x2F],
        ]);

        let ns = NvmeNamespace {
            id: first_nsid,
            lba_size,
            capacity_lba: nsze,
        };
        Ok(Some(ns))
    }

    fn create_io_queues(&self, qsize: u16) -> Result<(), &'static str> {
        // Allocate CQ then SQ queues for qid=1
        let mut ioq = Queue::new(1, qsize)?;

        // Admin: Create I/O Completion Queue (qid=1)
        let mut create_cq = NvmeSubmission::default();
        create_cq.opcode = OPC_CREATE_IO_CQ;
        create_cq.cdw10 = ((qsize as u32 - 1) & 0xFFFF) | ((ioq.qid as u32) << 16);
        // cdw11: IV=0 (MSI-X vector 0 if wired), | PC (physically contiguous) | IEN (interrupts enabled)
        // set IEN=1, PC=1
        create_cq.cdw11 = (1 << 1) | (1 << 0);

        // PRP points to CQ memory
        create_cq.prp1 = ioq.cq.phys();
        let _ = self.admin_submit_sync(create_cq, 0, None)?;

        // Admin: Create I/O Submission Queue (qid=1)
        let mut create_sq = NvmeSubmission::default();
        create_sq.opcode = OPC_CREATE_IO_SQ;
        create_sq.cdw10 = ((qsize as u32 - 1) & 0xFFFF) | ((ioq.qid as u32) << 16);
        // cdw11: PC=1 | CQID=1
        create_sq.cdw11 = (1 << 0) | ((ioq.qid as u32) << 16);
        create_sq.prp1 = ioq.sq.phys();

        let _ = self.admin_submit_sync(create_sq, 0, None)?;

        // Store IO queue
        *self.io.lock() = Some(ioq);
        Ok(())
    }

    fn build_prps(&self, len: usize, buf_pa: PhysAddr) -> Result<(u64, u64), &'static str> {
        // DEV NOTE** NVMe PRP: prp1 points to first page; prp2 points to either second page or PRP list.
        // For our DMA buffers, we require they are contiguous, but len may exceed 2 pages.
        // If len <= 2*PAGE_SIZE - offset, we can use prp1/prp2 directly; else we create a PRP list.
        let base = buf_pa.as_u64();
        let first_page_offset = (base as usize) & (PAGE_SIZE - 1);
        let first_page_remaining = PAGE_SIZE - first_page_offset;
        if len <= first_page_remaining {
            // Single page fits
            return Ok((base, 0));
        }
        let len_after_first = len - first_page_remaining;
        if len_after_first <= PAGE_SIZE {
            // Fits within 2 pages
            let prp2 = (base & !((PAGE_SIZE as u64) - 1)) + PAGE_SIZE as u64;
            return Ok((base, prp2));
        }

        // Need a PRP list
        // Compute how many additional pages after first
        let mut remaining = len_after_first;
        let mut pages_needed = (remaining + PAGE_SIZE - 1) / PAGE_SIZE;

        // Each PRP list entry is 8 bytes; one 4K page can hold 512 entries.
        let entries_needed = pages_needed as usize;
        let prp_list_bytes = ((entries_needed * 8) + PAGE_SIZE - 1) / PAGE_SIZE * PAGE_SIZE;
        let (pl_va, pl_pa) = alloc_dma_coherent(prp_list_bytes)?;
        unsafe { ptr::write_bytes(pl_va.as_mut_ptr::<u8>(), 0, prp_list_bytes); }

        // Fill PRP entries starting at second page boundary of the data buffer
        let mut entry_ptr = pl_va.as_mut_ptr::<u64>();
        let mut next_page_addr = (base & !((PAGE_SIZE as u64) - 1)) + PAGE_SIZE as u64;

        for i in 0..entries_needed {
            unsafe { ptr::write_volatile(entry_ptr.add(i), next_page_addr); }
            next_page_addr += PAGE_SIZE as u64;
        }

        Ok((base, pl_pa.as_u64()))
    }

    pub fn read(&self, lba: u64, count: u16, buf_pa: PhysAddr) -> Result<(), &'static str> {
        let ns = self.ns.as_ref().ok_or("NVMe: namespace not ready")?;
        let mut io = self.io.lock();
        let q = io.as_mut().ok_or("NVMe: IO queue not ready")?;

        // Prepare command
        let mut cmd = NvmeSubmission::default();
        cmd.opcode = OPC_READ;
        cmd.nsid = ns.id;

        // cdw10: SLBA[31:0], cdw11: SLBA[63:32]
        cmd.cdw10 = (lba & 0xFFFF_FFFF) as u32;
        cmd.cdw11 = ((lba >> 32) & 0xFFFF_FFFF) as u32;

        // cdw12: NLB (zero-based) -> number of logical blocks - 1
        cmd.cdw12 = (count as u32 - 1) & 0xFFFF;

        // Wire PRP
        let bytes = count as usize * ns.lba_size as usize;
        let (prp1, prp2) = self.build_prps(bytes, buf_pa)?;
        cmd.prp1 = prp1;
        cmd.prp2 = prp2;

        // Submit to IO SQ
        cmd.cid = q.sq_tail;
        let sq_idx = q.sq_next_index();
        unsafe { ptr::write_volatile(q.sq_entries.add(sq_idx), cmd); }
        q.sq_tail = q.sq_tail.wrapping_add(1);
        self.ring_sq_tail(q.qid, q.sq_tail);

        // Poll IO CQ for CID
        self.poll_cq(q, q.qid, cmd.cid)?;
        self.stats.commands_completed = self.stats.commands_completed.wrapping_add(1);
        self.stats.bytes_read = self.stats.bytes_read.wrapping_add(bytes as u64);
        Ok(())
    }

    pub fn write(&self, lba: u64, count: u16, buf_pa: PhysAddr) -> Result<(), &'static str> {
        let ns = self.ns.as_ref().ok_or("NVMe: namespace not ready")?;
        let mut io = self.io.lock();
        let q = io.as_mut().ok_or("NVMe: IO queue not ready")?;

        let mut cmd = NvmeSubmission::default();
        cmd.opcode = OPC_WRITE;
        cmd.nsid = ns.id;
        cmd.cdw10 = (lba & 0xFFFF_FFFF) as u32;
        cmd.cdw11 = ((lba >> 32) & 0xFFFF_FFFF) as u32;
        cmd.cdw12 = (count as u32 - 1) & 0xFFFF;

        let bytes = count as usize * ns.lba_size as usize;
        let (prp1, prp2) = self.build_prps(bytes, buf_pa)?;
        cmd.prp1 = prp1;
        cmd.prp2 = prp2;

        // Submit
        cmd.cid = q.sq_tail;
        let sq_idx = q.sq_next_index();
        unsafe { ptr::write_volatile(q.sq_entries.add(sq_idx), cmd); }
        q.sq_tail = q.sq_tail.wrapping_add(1);
        self.ring_sq_tail(q.qid, q.sq_tail);

        self.poll_cq(q, q.qid, cmd.cid)?;
        self.stats.commands_completed = self.stats.commands_completed.wrapping_add(1);
        self.stats.bytes_written = self.stats.bytes_written.wrapping_add(bytes as u64);
        Ok(())
    }

    pub fn get_stats(&self) -> NvmeStats {
        self.stats.clone()
    }
}

// Public API surface consistent with existing module exports

static NVME_ONCE: spin::Once<&'static Mutex<NvmeController>> = spin::Once::new();

pub fn init_nvme() -> Result<(), &'static str> {
    // Find NVMe controller by PCI class/subclass/progif
    let devices = crate::drivers::pci::scan_and_collect();
    let dev = devices.into_iter().find(|d| d.class == NVME_CLASS && d.subclass == NVME_SUBCLASS && d.progif == NVME_PROGIF)
        .ok_or("No NVMe controller found")?;

    let ctrl = NvmeController::init(dev)?;
    NVME_ONCE.call_once(|| ctrl);
    crate::log::logger::log_critical("✓ NVMe subsystem initialized");
    Ok(())
}

pub fn get_controller() -> Option<&'static NvmeController> {
    NVME_ONCE.get().map(|m| &*m.lock())
}

pub struct NvmeDriver;
impl NvmeDriver {
    pub fn read_blocks(ns_lba: u64, count: u16, dst_pa: PhysAddr) -> Result<(), &'static str> {
        let ctrl = NVME_ONCE.get().ok_or("NVMe not initialized")?;
        ctrl.lock().read(ns_lba, count, dst_pa)
    }
    pub fn write_blocks(ns_lba: u64, count: u16, src_pa: PhysAddr) -> Result<(), &'static str> {
        let ctrl = NVME_ONCE.get().ok_or("NVMe not initialized")?;
        ctrl.lock().write(ns_lba, count, src_pa)
    }
}
