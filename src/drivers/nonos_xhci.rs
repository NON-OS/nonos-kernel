//! xHCI (USB 3.x) Host Controller Driver

use core::{mem, ptr};
use core::sync::atomic::{AtomicU64, Ordering};
use alloc::{boxed::Box, vec, vec::Vec};
use spin::Mutex;
use x86_64::{PhysAddr, VirtAddr};

use crate::drivers::pci::{self, PciBar, PciDevice};
use crate::memory::dma::alloc_dma_coherent;
use crate::memory::mmio::{mmio_r32, mmio_r64, mmio_w32, mmio_w64};

// Constants
const XHCI_CLASS: u8 = 0x0C;
const XHCI_SUBCLASS: u8 = 0x03;
const XHCI_PROGIF: u8 = 0x30;

// Capability registers (relative to CAP base)
const CAP_CAPLENGTH: usize = 0x00;   // CAPLENGTH (byte) + Reserved (byte) + HCIVERSION 
const CAP_HCSPARAMS1: usize = 0x04;  // Structural Params 1
const CAP_HCSPARAMS2: usize = 0x08;  // Structural Params 2
const CAP_HCSPARAMS3: usize = 0x0C;  // Structural Params 3
const CAP_HCCPARAMS1: usize = 0x10;  // Capability Params 1
const CAP_DBOFF: usize = 0x14;       // Doorbell offset
const CAP_RTSOFF: usize = 0x18;      // Runtime registers offset
const CAP_HCCPARAMS2: usize = 0x1C;  // Capability Params 2

// Operational registers (relative to OP base)
const OP_USBCMD: usize = 0x00;
const OP_USBSTS: usize = 0x04;
const OP_PAGESIZE: usize = 0x08;
const OP_DNCTRL: usize = 0x14;
const OP_CRCR: usize = 0x18;
const OP_DCBAAP: usize = 0x30;
const OP_CONFIG: usize = 0x38;
// Port register block starts at 0x400 with stride 0x10
const OP_PORTSC_BASE: usize = 0x400;
const OP_PORT_REG_STRIDE: usize = 0x10;

// USBCMD bits
const USBCMD_RS: u32 = 1 << 0;    // Run/Stop
const USBCMD_HCRST: u32 = 1 << 1; // Host Controller Reset
const USBCMD_INTE: u32 = 1 << 2;  // Interrupt Enable

// USBSTS bits
const USBSTS_HCH: u32 = 1 << 0;  // HC Halted
const USBSTS_HSE: u32 = 1 << 2;  // Host System Error
const USBSTS_EINT: u32 = 1 << 3; // Event Interrupt
const USBSTS_PCD: u32 = 1 << 4;  // Port Change Detect
const USBSTS_CNR: u32 = 1 << 11; // Controller Not Ready

// PortSC bits (subset)
const PORTSC_CCS: u32 = 1 << 0;    // Current Connect Status
const PORTSC_PED: u32 = 1 << 1;    // Port Enabled/Disabled
const PORTSC_OCA: u32 = 1 << 3;    // Over-Current Active
const PORTSC_PR: u32 = 1 << 4;     // Port Reset
const PORTSC_PLS_MASK: u32 = 0xF << 5; // Port Link State
const PORTSC_CSC: u32 = 1 << 17;   // Connect Status Change
const PORTSC_PEC: u32 = 1 << 18;   // Port Enable/Disable Change
const PORTSC_WRC: u32 = 1 << 19;   // Warm Port Reset Change
const PORTSC_PRC: u32 = 1 << 21;   // Port Reset Change

// Runtime registers (relative to RT base)
const RT_MFINDEX: usize = 0x00;
const RT_IR0_IMAN: usize = 0x20;    // Interrupter 0 IMAN
const RT_IR0_IMOD: usize = 0x24;    // Interrupter 0 IMOD
const RT_IR0_ERSTSZ: usize = 0x28;  // ERST Size
const RT_IR0_ERSTBA: usize = 0x30;  // ERST Base Address
const RT_IR0_ERDP: usize = 0x38;    // Event Ring Dequeue Pointer

// IMAN bits
const IMAN_IP: u32 = 1 << 0;  // Interrupt Pending
const IMAN_IE: u32 = 1 << 1;  // Interrupt Enable

// TRB types
pub const TRB_TYPE_NORMAL: u32 = 1;
const TRB_TYPE_SETUP_STAGE: u32 = 2;
const TRB_TYPE_DATA_STAGE: u32 = 3;
const TRB_TYPE_STATUS_STAGE: u32 = 4;
const TRB_TYPE_LINK: u32 = 6;
const TRB_TYPE_ENABLE_SLOT_CMD: u32 = 9;
const TRB_TYPE_ADDRESS_DEVICE_CMD: u32 = 11;

// Control TRB specifics
const TRB_DIR_IN: u32 = 1 << 16; // For DATA_STAGE direction
pub const TRB_IOC: u32 = 1 << 5;     // Interrupt On Completion
const TRB_ENT: u32 = 1 << 1;     // Evaluate Next TRB (for chained)

// Command Ring Control Register flags
const CRCR_RCS: u64 = 1 << 0; // Ring Cycle State
const CRCR_CS: u64 = 1 << 1;  // Command Stop
const CRCR_CA: u64 = 1 << 2;  // Command Abort

// ERDP flags
const ERDP_EHB: u64 = 1 << 3; // Event Handler Busy

// Context entries and sizes
const MAX_SLOTS: usize = 256;
const SLOT_ID_MIN: u8 = 1;

// Max packet sizes by speed (PortSC speed bits 10..13)
const PS_FULL: u32 = 1;  // FS
const PS_LOW: u32 = 2;   // LS
const PS_HIGH: u32 = 3;  // HS
const PS_SUPER: u32 = 4; // SS (USB 3.x)

// DMA helpers
struct DmaRegion {
    va: VirtAddr,
    pa: PhysAddr,
    size: usize,
}
impl DmaRegion {
    fn new(size: usize, zero: bool) -> Result<Self, &'static str> {
        let (va, pa) = alloc_dma_coherent(size)?;
        if zero {
            unsafe { ptr::write_bytes(va.as_mut_ptr::<u8>(), 0, size); }
        }
        Ok(Self { va, pa, size })
    }
    #[inline] fn as_mut_ptr<T>(&self) -> *mut T { self.va.as_mut_ptr::<T>() }
    #[inline] fn phys(&self) -> u64 { self.pa.as_u64() }
}

// TRB: 16 bytes
#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct Trb {
    pub d0: u32,
    pub d1: u32,
    pub d2: u32,
    pub d3: u32,
}
impl Default for Trb {
    fn default() -> Self { Trb { d0: 0, d1: 0, d2: 0, d3: 0 } }
}
impl Trb {
    pub fn set_type(&mut self, trb_type: u32) {
        self.d3 = (self.d3 & !(0x3F << 10)) | ((trb_type & 0x3F) << 10);
    }
    pub fn set_cycle(&mut self, cycle: bool) {
        if cycle { self.d3 |= 1; } else { self.d3 &= !1; }
    }
    fn get_type(&self) -> u32 { (self.d3 >> 10) & 0x3F }
    fn get_cycle(&self) -> bool { (self.d3 & 1) != 0 }
}

// ERST entry
#[repr(C, packed)]
struct ErstEntry {
    ring_base_lo: u32,
    ring_base_hi: u32,
    ring_size: u32,
    rsvd: u32,
}

// Slot/Endpoint contexts (assume 64-byte contexts if CSZ=1)
#[repr(C, align(32))]
#[derive(Clone, Copy)]
struct SlotContext {
    // DW0
    route_str: u32,
    // DW1
    speed: u32,
    // DW2
    rsvd2: u32,
    // DW3
    rsvd3: u32,
    // DW4
    tt_hub_slot: u32,
    // DW5
    tt_port_num: u32,
    // DW6
    root_hub_port: u32,
    // DW7
    num_ports: u32,
    // DW8-15 reserved for 64-byte ctx
    rsvd_rest: [u32; 8],
}

#[repr(C, align(32))]
#[derive(Clone, Copy)]
struct EpContext {
    // DW0
    ep_state: u32,
    // DW1
    mult_max_pstreams_lsa_interval: u32,
    // DW2
    ep_type_maxburst_maxpkt: u32,
    // DW3
    deq_ptr_lo: u32,
    // DW4
    deq_ptr_hi: u32,
    // DW5
    avg_trb_len: u32,
    // DW6-7 reserved
    rsvd: [u32; 2],
}

#[repr(C, align(64))]
struct DeviceContext {
    slot: SlotContext,
    ep0: EpContext,
    // other endpoints omitted 
    rest: [u8; 64 * 30], // ensure room for endpoints up to EP31 if needed
}

#[repr(C, align(64))]
struct InputControlContext {
    drop_flags: u32,
    add_flags: u32,
    rsvd: [u32; 6],
    // then slot + ep contexts follow
}

#[repr(C, align(64))]
struct InputContext {
    icc: InputControlContext,
    slot: SlotContext,
    ep0: EpContext,
    rest: [u8; 64 * 30],
}

// Rings
pub struct TransferRing {
    trbs: DmaRegion,
    pub cycle: bool,
    enqueue_index: usize,
    ring_size: usize,
}
impl TransferRing {
    fn new(entries: usize) -> Result<Self, &'static str> {
        let bytes = entries * mem::size_of::<Trb>();
        let trbs = DmaRegion::new(bytes, true)?;
        // Initialize Link TRB at end to wrap
        unsafe {
            let trb_ptr = trbs.as_mut_ptr::<Trb>();
            // Link TRB at last index
            let link = trb_ptr.add(entries - 1);
            (*link) = Trb::default();
            let addr = trbs.phys() as u64;
            // The link points to start (addr), 64-byte aligned
            (*link).d0 = (addr & 0xFFFF_FFFF) as u32;
            (*link).d1 = (addr >> 32) as u32;
            (*link).d2 = 0;
            // Set Link TRB, toggle cycle bit
            (*link).d3 = (TRB_TYPE_LINK << 10) | (1 << 1); // ENT for toggle?
        }
        Ok(Self {
            trbs,
            cycle: true,
            enqueue_index: 0,
            ring_size: entries,
        })
    }

    pub fn enqueue(&mut self, mut trb: Trb) -> u64 {
        // Place TRB with current cycle
        let idx = self.enqueue_index;
        unsafe {
            let ptr_trb = self.trbs.as_mut_ptr::<Trb>().add(idx);
            trb.set_cycle(self.cycle);
            ptr::write_volatile(ptr_trb, trb);
        }
        // Compute physical address of this TRB (used to match events)
        let phys = self.trbs.phys() + (idx * mem::size_of::<Trb>()) as u64;

        // Advance
        self.enqueue_index += 1;
        if self.enqueue_index == self.ring_size - 1 {
            // Next is Link TRB; toggle cycle and wrap
            self.cycle = !self.cycle;
            self.enqueue_index = 0;
        }
        phys
    }

    fn dequeue_ptr(&self) -> u64 {
        // For endpoint contexts, the dequeue pointer is the ring base | cycle bit
        (self.trbs.phys()) | (self.cycle as u64)
    }
}

struct EventRing {
    ring: DmaRegion,
    erst: DmaRegion,
    size: usize,
    dequeue_index: usize,
    cycle: bool,
}
impl EventRing {
    fn new(entries: usize) -> Result<Self, &'static str> {
        let bytes = entries * mem::size_of::<Trb>();
        let ring = DmaRegion::new(bytes, true)?;
        let erst = DmaRegion::new(mem::size_of::<ErstEntry>(), true)?;

        // Program single-segment ERST entry
        unsafe {
            let e = &mut *erst.as_mut_ptr::<ErstEntry>();
            e.ring_base_lo = (ring.phys() & 0xFFFF_FFFF) as u32;
            e.ring_base_hi = (ring.phys() >> 32) as u32;
            e.ring_size = entries as u32;
            e.rsvd = 0;
        }

        Ok(Self {
            ring,
            erst,
            size: entries,
            dequeue_index: 0,
            cycle: true,
        })
    }

    fn trb_at(&self, idx: usize) -> Trb {
        unsafe {
            let p = self.ring.as_mut_ptr::<Trb>().add(idx);
            ptr::read_volatile(p)
        }
    }

    fn advance(&mut self) {
        self.dequeue_index += 1;
        if self.dequeue_index == self.size {
            self.dequeue_index = 0;
            self.cycle = !self.cycle;
        }
    }

    fn current_dequeue_phys(&self) -> u64 {
        self.ring.phys() + (self.dequeue_index * mem::size_of::<Trb>()) as u64
    }
}

pub struct XhciController {
    pci: PciDevice,
    cap_base: usize,
    op_base: usize,
    rt_base: usize,
    pub db_base: usize,

    max_slots: u8,
    context_size_64: bool,
    pub num_ports: u8,

    // Rings and contexts
    cmd_ring: TransferRing,
    evt_ring: EventRing,

    dcbaa: DmaRegion, // array[MaxSlots+1] of u64
    scratchpad_ptrs: Option<DmaRegion>,
    scratchpad_buffers: Vec<DmaRegion>,

    // Device state (single device for now)
    slot_id: u8,
    pub ep0_ring: Option<TransferRing>,

    // Stats
    interrupts: AtomicU64,
    commands_completed: AtomicU64,
    transfers_completed: AtomicU64,
}

pub static XHCI_ONCE: spin::Once<&'static Mutex<XhciController>> = spin::Once::new();

impl XhciController {
    pub fn get_stats(&self) -> XhciStats {
        XhciStats {
            transfers: self.transfers_completed.load(Ordering::Relaxed),
            errors: 0,
            interrupts: self.interrupts.load(Ordering::Relaxed),
            bytes_transferred: 0, // Missing implement of bytes tracking
            devices_connected: 1,
            max_slots: 32, // NEXT DEVELOPMENT: get from controller capabilities
            max_ports: 8,  // ****                                          ****
        }
    }
    pub fn init(pci: PciDevice) -> Result<&'static Mutex<Self>, &'static str> {
        let bar = pci.get_bar(0)?;
        let cap_base = match bar {
            PciBar::Memory { address, .. } => address.as_u64() as usize,
            _ => return Err("xHCI BAR0 is not MMIO"),
        };

        // Parse capabilities
        let caplen = unsafe { mmio_r32(cap_base + CAP_CAPLENGTH) } & 0xFF;
        let hcs1 = unsafe { mmio_r32(cap_base + CAP_HCSPARAMS1) };
        let hcs2 = unsafe { mmio_r32(cap_base + CAP_HCSPARAMS2) };
        let hcc1 = unsafe { mmio_r32(cap_base + CAP_HCCPARAMS1) };
        let dboff = unsafe { mmio_r32(cap_base + CAP_DBOFF) };
        let rtsoff = unsafe { mmio_r32(cap_base + CAP_RTSOFF) };

        let op_base = cap_base + caplen as usize;
        let db_base = cap_base + dboff as usize;
        let rt_base = cap_base + rtsoff as usize;

        let max_slots = (hcs1 & 0xFF) as u8;
        let num_ports = ((hcs1 >> 24) & 0xFF) as u8;
        let csz = ((hcc1 >> 2) & 1) != 0; // Context Size 1=64B

        // Stop & Reset controller
        let mut cmd = unsafe { mmio_r32(op_base + OP_USBCMD) };
        cmd &= !USBCMD_RS;
        unsafe { mmio_w32(op_base + OP_USBCMD, cmd); }

        // Wait HCH set
        if !Self::spin_wait(|| unsafe { mmio_r32(op_base + OP_USBSTS) } & USBSTS_HCH != 0, 1_000_000) {
            return Err("xHCI: HC did not halt");
        }

        // Host Controller Reset
        unsafe {
            mmio_w32(op_base + OP_USBCMD, USBCMD_HCRST);
        }
        if !Self::spin_wait(|| unsafe { mmio_r32(op_base + OP_USBCMD) } & USBCMD_HCRST == 0, 1_000_000) {
            return Err("xHCI: HCRST did not clear");
        }
        if !Self::spin_wait(|| unsafe { mmio_r32(op_base + OP_USBSTS) } & USBSTS_CNR == 0, 1_000_000) {
            return Err("xHCI: Controller Not Ready stayed set");
        }

        // Program PAGESIZE (host supports 4K)
        unsafe { mmio_w32(op_base + OP_PAGESIZE, 1); } // 2^12

        // Create command ring and event ring
        let cmd_ring = TransferRing::new(256)?;
        let evt_ring = EventRing::new(256)?;

        // DCBAA allocation: (MaxSlots+1) * 8 bytes
        let dcbaa_bytes = ((max_slots as usize) + 1) * 8;
        let dcbaa = DmaRegion::new(dcbaa_bytes, true)?;

        // Scratchpad buffers if required
        let max_scratch = ((hcs2 >> 27) & 0x1F) as usize | (((hcs2 >> 21) & 0x1F) as usize) << 5; // xHCI 1.1: Max Scratchpad via HCS2[26:21]+[31:27]
        let mut scratchpad_ptrs = None;
        let mut scratchpad_buffers = Vec::new();
        if max_scratch > 0 {
            // Allocate array of pointers (64-bit each)
            let arr_bytes = max_scratch * 8;
            let arr = DmaRegion::new(arr_bytes, true)?;
            for i in 0..max_scratch {
                let buf = DmaRegion::new(4096, true)?;
                unsafe {
                    let p = arr.as_mut_ptr::<u64>().add(i);
                    ptr::write_volatile(p, buf.phys());
                }
                scratchpad_buffers.push(buf);
            }
            // DCBAA[0] = scratchpad array pointer
            unsafe {
                let p = dcbaa.as_mut_ptr::<u64>();
                ptr::write_volatile(p, arr.phys());
            }
            scratchpad_ptrs = Some(arr);
        }

        // Program DCBAAP
        unsafe { mmio_w64(op_base + OP_DCBAAP, dcbaa.phys()); }

        // Program Command Ring (CRCR)
        unsafe {
            // Clear any old value first
            mmio_w64(op_base + OP_CRCR, 0);
            // Write base | RCS=1
            mmio_w64(op_base + OP_CRCR, (cmd_ring.trbs.phys() & !0x3F) | CRCR_RCS);
        }

        // Program Event Ring (Runtime, Interrupter 0)
        unsafe {
            // ERSTSZ
            mmio_w32(rt_base + RT_IR0_ERSTSZ, 1);
            // ERSTBA
            mmio_w64(rt_base + RT_IR0_ERSTBA, evt_ring.erst.phys());
            // ERDP = dequeue pointer | EHB=1 clear
            mmio_w64(rt_base + RT_IR0_ERDP, evt_ring.current_dequeue_phys());
            // Enable IMAN.IE
            let mut iman = mmio_r32(rt_base + RT_IR0_IMAN);
            iman |= IMAN_IE;
            mmio_w32(rt_base + RT_IR0_IMAN, iman);
        }

        // Enable doorbell and interrupts, run controller
        unsafe {
            let mut usbcmd = mmio_r32(op_base + OP_USBCMD);
            usbcmd |= USBCMD_INTE | USBCMD_RS;
            mmio_w32(op_base + OP_USBCMD, usbcmd);
        }

        // Create controller struct
        let mut ctrl = XhciController {
            pci,
            cap_base,
            op_base,
            rt_base,
            db_base,
            max_slots,
            context_size_64: csz,
            num_ports,
            cmd_ring,
            evt_ring,
            dcbaa,
            scratchpad_ptrs,
            scratchpad_buffers,
            slot_id: 0,
            ep0_ring: None,
            interrupts: AtomicU64::new(0),
            commands_completed: AtomicU64::new(0),
            transfers_completed: AtomicU64::new(0),
        };

        // Enumerate first connected port
        ctrl.enumerate_first_device()?;

        let boxed = Box::leak(Box::new(Mutex::new(ctrl)));
        XHCI_ONCE.call_once(|| boxed);
        Ok(boxed)
    }

    fn spin_wait<F: Fn() -> bool>(cond: F, mut spins: u32) -> bool {
        while spins > 0 {
            if cond() { return true; }
            spins -= 1;
        }
        false
    }

    fn port_reg(&self, port: u8, off: usize) -> usize {
        self.op_base + OP_PORTSC_BASE + (port as usize - 1) * OP_PORT_REG_STRIDE + off
    }

    fn read_portsc(&self, port: u8) -> u32 {
        unsafe { mmio_r32(self.port_reg(port, 0)) }
    }

    fn write_portsc(&self, port: u8, val: u32) {
        unsafe { mmio_w32(self.port_reg(port, 0), val); }
    }

    fn enumerate_first_device(&mut self) -> Result<(), &'static str> {
        // Find first connected port
        let mut found_port = 0u8;
        for p in 1..=self.num_ports {
            let sc = self.read_portsc(p);
            if (sc & PORTSC_CCS) != 0 {
                found_port = p;
                break;
            }
        }
        if found_port == 0 {
            return Err("xHCI: no connected device on any port");
        }

        // Clear change bits
        let mut sc = self.read_portsc(found_port);
        sc |= PORTSC_CSC | PORTSC_PEC | PORTSC_PRC | PORTSC_WRC;
        self.write_portsc(found_port, sc);

        // Reset port
        sc = self.read_portsc(found_port);
        sc = (sc & !PORTSC_PLS_MASK) | PORTSC_PR; // set PR
        self.write_portsc(found_port, sc);

        // Wait for PRC and PED
        if !Self::spin_wait(|| {
            let v = self.read_portsc(found_port);
            (v & PORTSC_PRC) != 0 && (v & PORTSC_PED) != 0
        }, 2_000_000) {
            return Err("xHCI: port reset timeout");
        }

        // Clear change bits again
        sc = self.read_portsc(found_port);
        sc |= PORTSC_CSC | PORTSC_PEC | PORTSC_PRC | PORTSC_WRC;
        self.write_portsc(found_port, sc);

        // Enable Slot
        let slot_id = self.cmd_enable_slot()?;

        // Address Device (creates device context, ep0 ring, etc.)
        self.address_device(slot_id, found_port)?;

        // Create EP0 transfer ring
        self.ep0_ring = Some(TransferRing::new(64)?);

        // Ring doorbell to arm EP0 after setting dequeue pointer (done in address_device)

        // Perform a GET_DESCRIPTOR(Device) to verify control xfer
        let mut buf = DmaRegion::new(64, true)?;
        let len = self.ctrl_get_descriptor_device(slot_id, &mut buf)?;

        let data = unsafe { core::slice::from_raw_parts(buf.va.as_ptr::<u8>(), len) };
        crate::log::logger::log_critical(&format!("xHCI: Device descriptor ({} bytes): {:02x?}", len, &data[..len]));

        Ok(())
    }

    fn cmd_enqueue_and_ring(&mut self, trb: Trb) -> u64 {
        let ptr_phys = self.cmd_ring.enqueue(trb);
        // Ring doorbell for command ring is doorbell[0] with value 0
        unsafe {
            mmio_w32(self.db_base + 0 * 4, 0);
        }
        ptr_phys
    }

    fn wait_command_completion(&mut self, cmd_trb_ptr: u64) -> Result<(), &'static str> {
        // Poll event ring for Command Completion Event that references our command TRB pointer
        let mut spins = 2_000_000u32;
        loop {
            // Read IMAN.IP; optionally handle interrupts in future
            let iman = unsafe { mmio_r32(self.rt_base + RT_IR0_IMAN) };
            if (iman & IMAN_IP) != 0 {
                // Clear pending by writing 1 to IP
                unsafe { mmio_w32(self.rt_base + RT_IR0_IMAN, iman | IMAN_IP); }
            }

            let trb = self.evt_ring.trb_at(self.evt_ring.dequeue_index);
            let cycle = trb.get_cycle();
            if cycle == self.evt_ring.cycle {
                let trb_type = trb.get_type();
                match trb_type {
                    // Command Completion Event type=33 decimal, but spec: 0x21. 
                    _ => {
                        let event_trb_ptr = trb.d0 as u64 | ((trb.d1 as u64) << 32);
                        // Advance ring
                        self.evt_ring.advance();
                        // Update ERDP with EHB clear
                        unsafe { mmio_w64(self.rt_base + RT_IR0_ERDP, self.evt_ring.current_dequeue_phys() | ERDP_EHB); }
                        if event_trb_ptr == (cmd_trb_ptr & !0xF) {
                            // Check completion code in d2[31:24]
                            let ccode = (trb.d2 >> 24) & 0xFF;
                            if ccode != 1 { // 1 = Success
                                return Err("xHCI: command completion with error");
                            }
                            self.commands_completed.fetch_add(1, Ordering::Relaxed);
                            return Ok(());
                        } else {
                            // Another event (e.g., transfer), continue
                        }
                    }
                }
            }

            if spins == 0 {
                return Err("xHCI: command completion timeout");
            }
            spins -= 1;
        }
    }

    fn cmd_enable_slot(&mut self) -> Result<u8, &'static str> {
        // Enable Slot Command TRB
        let mut trb = Trb::default();
        trb.set_type(TRB_TYPE_ENABLE_SLOT_CMD);
        trb.set_cycle(self.cmd_ring.cycle);
        let cmd_ptr = self.cmd_enqueue_and_ring(trb);
        self.wait_command_completion(cmd_ptr)?;

        // DEV NOTE** We need slot ID from the event; store last known by re-reading last event
        // Here we issue a read of prior event again is tricky; instead we will
        // do a best-effort: xHCI usually places Slot ID in event d3[31:24].
        // To capture it deterministically, we peek the last advanced TRB (previous index)
        let idx = if self.evt_ring.dequeue_index == 0 { self.evt_ring.size - 1 } else { self.evt_ring.dequeue_index - 1 };
        let evt = self.evt_ring.trb_at(idx);
        let slot_id = ((evt.d3 >> 24) & 0xFF) as u8;
        if slot_id < SLOT_ID_MIN || slot_id > self.max_slots {
            return Err("xHCI: invalid Slot ID returned");
        }
        self.slot_id = slot_id;
        Ok(slot_id)
    }

    fn address_device(&mut self, slot_id: u8, port_id: u8) -> Result<(), &'static str> {
        // Create Input Context
        let ic_bytes = mem::size_of::<InputContext>();
        let ic = DmaRegion::new(ic_bytes, true)?;

        // Prepare Slot Context
        let portsc = self.read_portsc(port_id);
        let speed = (portsc >> 10) & 0xF;

        unsafe {
            let icp = ic.as_mut_ptr::<InputContext>();
            // ICC add flags: add slot (bit 0) and EP0 (bit 1)
            (*icp).icc.add_flags = 0b11;
            (*icp).icc.drop_flags = 0;
            // Slot
            (*icp).slot.route_str = 0;
            (*icp).slot.speed = speed;
            (*icp).slot.root_hub_port = port_id as u32;
            (*icp).slot.num_ports = 1;
            // EP0 context
            let mps = match speed {
                PS_LOW | PS_FULL => 8,
                PS_HIGH => 64,
                PS_SUPER => 512,
                _ => 8,
            } as u32;
            // ep_type: Control (value 4 << 3 in spec combined), here put in upper bits as per xHCI ctx layout:
            // ep_type in bits [10:8] of DW2
            (*icp).ep0.ep_type_maxburst_maxpkt = (4 << 8) | (mps & 0xFFFF);
            // Dequeue pointer will be set after ring allocation (later), for address device it's allowed to be 0
        }

        // Program DCBAA Slot entry with a new Device Context buffer
        let dc_bytes = mem::size_of::<DeviceContext>();
        let dc = DmaRegion::new(dc_bytes, true)?;
        unsafe {
            let dcb = self.dcbaa.as_mut_ptr::<u64>().add(slot_id as usize);
            ptr::write_volatile(dcb, dc.phys());
        }

        // Issue Address Device command
        let mut trb = Trb::default();
        // Input Context pointer in d0/d1
        trb.d0 = (ic.phys() & 0xFFFF_FFFF) as u32;
        trb.d1 = (ic.phys() >> 32) as u32;
        // d2: SlotID in [31:24]
        trb.d2 = (slot_id as u32) << 24;
        trb.set_type(TRB_TYPE_ADDRESS_DEVICE_CMD);
        let cmd_ptr = self.cmd_enqueue_and_ring(trb);
        self.wait_command_completion(cmd_ptr)?;

        // Now create EP0 transfer ring and set dequeue pointer in Device Context EP0
        let mut ep0 = TransferRing::new(64)?;
        let deq = ep0.dequeue_ptr();

        // Update Device Context EP0 dequeue pointer with DCS=1 (bit 0)
        unsafe {
            let dcp = dc.as_mut_ptr::<DeviceContext>();
            (*dcp).ep0.deq_ptr_lo = (deq & 0xFFFF_FFFF) as u32;
            (*dcp).ep0.deq_ptr_hi = (deq >> 32) as u32;
        }

        self.ep0_ring = Some(ep0);
        Ok(())
    }

    fn ctrl_get_descriptor_device(&mut self, slot_id: u8, out: &mut DmaRegion) -> Result<usize, &'static str> {
        // Build Setup, Data, Status TRBs on EP0 ring
        let ep0 = self.ep0_ring.as_mut().ok_or("xHCI: EP0 ring not ready")?;

        // Setup packet: bmRequestType=0x80 (IN, standard, device), bRequest=GET_DESCRIPTOR(6), wValue=DEVICE(1)<<8, wIndex=0, wLength=18
        let bm_req_type = 0x80u8;
        let b_request = 0x06u8;
        let w_value = 0x0100u16;
        let w_index = 0x0000u16;
        let w_length = 18u16;

        // Setup Stage TRB encodes 8 bytes of setup packet into d0/d1
        let mut setup = Trb::default();
        setup.d0 = (bm_req_type as u32)
            | ((b_request as u32) << 8)
            | ((w_value as u32) << 16);
        setup.d1 = (w_index as u32) | ((w_length as u32) << 16);
        // d2: TRT transfer type: IN data stage (2) in bits [17:16]
        setup.d2 = (2 << 16);
        // d3: Type + Cycle
        setup.set_type(TRB_TYPE_SETUP_STAGE);
        setup.set_cycle(ep0.cycle);

        // Data Stage TRB (IN, pointer to out buffer)
        let mut data = Trb::default();
        data.d0 = (out.phys() & 0xFFFF_FFFF) as u32;
        data.d1 = (out.phys() >> 32) as u32;
        data.d2 = w_length as u32; // Transfer length
        data.d3 = TRB_IOC | (TRB_TYPE_DATA_STAGE << 10) | 1; // cycle=1 later replaced by set_cycle
        data.set_cycle(ep0.cycle);

        // Status Stage TRB (OUT)
        let mut status = Trb::default();
        status.d2 = 0;
        status.set_type(TRB_TYPE_STATUS_STAGE);
        status.set_cycle(ep0.cycle);

        // Enqueue TRBs
        let _s_ptr = ep0.enqueue(setup);
        let _d_ptr = ep0.enqueue(data);
        let st_ptr = ep0.enqueue(status);

        // Ring doorbell for slot_id EP0: DB[slot_id] = 1 (endpoint 1 = EP0 OUT? For control, endpoint 1 = EP0)
        unsafe {
            mmio_w32(self.db_base + (slot_id as usize) * 4, 1);
        }

        // Wait for transfer event that references our Status TRB or check IOC on data TRB
        self.wait_transfer_completion(st_ptr)?;

        self.transfers_completed.fetch_add(1, Ordering::Relaxed);
        Ok(w_length as usize)
    }

    pub fn wait_transfer_completion(&mut self, trb_ptr_match: u64) -> Result<(), &'static str> {
        let mut spins = 2_000_000u32;
        loop {
            let iman = unsafe { mmio_r32(self.rt_base + RT_IR0_IMAN) };
            if (iman & IMAN_IP) != 0 {
                unsafe { mmio_w32(self.rt_base + RT_IR0_IMAN, iman | IMAN_IP); }
            }

            let trb = self.evt_ring.trb_at(self.evt_ring.dequeue_index);
            let cycle = trb.get_cycle();
            if cycle == self.evt_ring.cycle {
                let trb_type = trb.get_type();
                // Transfer Event is type 32 (0x20); but we match on pointer
                let event_trb_ptr = trb.d0 as u64 | ((trb.d1 as u64) << 32);
                // Advance ring and ERDP
                self.evt_ring.advance();
                unsafe { mmio_w64(self.rt_base + RT_IR0_ERDP, self.evt_ring.current_dequeue_phys() | ERDP_EHB); }

                if (event_trb_ptr & !0xF) == (trb_ptr_match & !0xF) {
                    let ccode = (trb.d2 >> 24) & 0xFF;
                    if ccode != 1 {
                        return Err("xHCI: transfer completion error");
                    }
                    return Ok(());
                }
            }

            if spins == 0 {
                return Err("xHCI: transfer completion timeout");
            }
            spins -= 1;
        }
    }
}

// Public API

#[derive(Default)]
pub struct XhciStats {
    pub transfers: u64,
    pub errors: u64,
    pub interrupts: u64,
    pub bytes_transferred: u64,
    pub devices_connected: u64,
    pub max_slots: u64,
    pub max_ports: u64,
}

pub fn init_xhci() -> Result<(), &'static str> {
    // Find xHCI controller
    let devices = pci::scan_and_collect();
    let dev = devices.into_iter().find(|d| d.class == XHCI_CLASS && d.subclass == XHCI_SUBCLASS && d.progif == XHCI_PROGIF)
        .ok_or("No xHCI controller found")?;

    let _ctrl = XhciController::init(dev)?;
    crate::log::logger::log_critical("✓ USB 3.0/xHCI subsystem initialized");
    Ok(())
}

pub struct XhciControllerHandle;

pub fn get_controller() -> Option<spin::MutexGuard<'static, XhciController>> {
    XHCI_ONCE.get().map(|m| m.lock())
}

impl XhciControllerHandle {
    pub fn get_stats() -> crate::drivers::nonos_xhci::XhciStats {
        if let Some(ctrl) = get_controller() {
            XhciStats {
                transfers: ctrl.transfers_completed.load(Ordering::Relaxed),
                errors: 0,
                interrupts: ctrl.interrupts.load(Ordering::Relaxed),
                bytes_transferred: 0,
                devices_connected: 1,
                max_slots: ctrl.max_slots as u64,
                max_ports: ctrl.num_ports as u64,
            }
        } else {
            XhciStats::default()
        }
    }
}

/// Perform USB control transfer with xHCI hardware implementation
pub fn control_transfer(
    slot_id: u8,
    setup_packet: [u8; 8],
    data_buffer: Option<&mut [u8]>,
    timeout_us: u32,
) -> Result<usize, &'static str> {
    if let Some(ctrl_mutex) = XHCI_ONCE.get() {
        let mut ctrl = ctrl_mutex.lock();
        let ep0 = ctrl.ep0_ring.as_mut().ok_or("xHCI: EP0 ring not initialized")?;
        
        // Parse setup packet
        let bm_request_type = setup_packet[0];
        let b_request = setup_packet[1];
        let w_value = u16::from_le_bytes([setup_packet[2], setup_packet[3]]);
        let w_index = u16::from_le_bytes([setup_packet[4], setup_packet[5]]);
        let w_length = u16::from_le_bytes([setup_packet[6], setup_packet[7]]);
        
        // Determine transfer direction
        let is_in = (bm_request_type & 0x80) != 0;
        let has_data_stage = w_length > 0;
        
        // Setup Stage TRB
        let mut setup_trb = Trb::default();
        setup_trb.d0 = (setup_packet[0] as u32)
            | ((setup_packet[1] as u32) << 8)
            | ((w_value as u32) << 16);
        setup_trb.d1 = (w_index as u32) | ((w_length as u32) << 16);
        
        if has_data_stage {
            setup_trb.d2 = if is_in { 2 << 16 } else { 3 << 16 }; // TRT: IN=2, OUT=3
        } else {
            setup_trb.d2 = 0; // No data stage
        }
        setup_trb.set_type(TRB_TYPE_SETUP_STAGE);
        setup_trb.set_cycle(ep0.cycle);
        
        let mut last_trb_ptr = ep0.enqueue(setup_trb);
        let mut bytes_transferred = 0;
        
        // Data Stage TRB (if needed)
        if has_data_stage && data_buffer.is_some() {
            let buffer = data_buffer.unwrap();
            let transfer_len = core::cmp::min(w_length as usize, buffer.len());
            
            // Create DMA buffer for the transfer
            let mut dma_buf = DmaRegion::new(transfer_len, true)
                .map_err(|_| "Failed to allocate DMA buffer")?;
            
            // For OUT transfers, copy data to DMA buffer
            if !is_in {
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        buffer.as_ptr(),
                        dma_buf.va.as_mut_ptr::<u8>(),
                        transfer_len
                    );
                }
            }
            
            let mut data_trb = Trb::default();
            data_trb.d0 = (dma_buf.phys() & 0xFFFF_FFFF) as u32;
            data_trb.d1 = (dma_buf.phys() >> 32) as u32;
            data_trb.d2 = transfer_len as u32;
            data_trb.d3 = TRB_IOC; // Interrupt on completion
            data_trb.set_type(TRB_TYPE_DATA_STAGE);
            data_trb.set_cycle(ep0.cycle);
            
            last_trb_ptr = ep0.enqueue(data_trb);
            
            // Status Stage TRB (opposite direction of data stage)
            let mut status_trb = Trb::default();
            status_trb.d2 = 0;
            status_trb.d3 = if is_in { 0 } else { TRB_IOC }; // Direction bit
            status_trb.set_type(TRB_TYPE_STATUS_STAGE);
            status_trb.set_cycle(ep0.cycle);
            
            last_trb_ptr = ep0.enqueue(status_trb);
            
            // Ring doorbell for EP0
            unsafe {
                mmio_w32(ctrl.db_base + (slot_id as usize) * 4, 1);
            }
            
            // Wait for completion
            ctrl.wait_transfer_completion(last_trb_ptr)?;
            
            // For IN transfers, copy data back from DMA buffer
            if is_in {
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        dma_buf.va.as_ptr::<u8>(),
                        buffer.as_mut_ptr(),
                        transfer_len
                    );
                }
            }
            
            bytes_transferred = transfer_len;
        } else {
            // No data stage, just status stage
            let mut status_trb = Trb::default();
            status_trb.d2 = 0;
            status_trb.d3 = TRB_IOC;
            status_trb.set_type(TRB_TYPE_STATUS_STAGE);
            status_trb.set_cycle(ep0.cycle);
            
            last_trb_ptr = ep0.enqueue(status_trb);
            
            // Ring doorbell
            unsafe {
                mmio_w32(ctrl.db_base + (slot_id as usize) * 4, 1);
            }
            
            // Wait for completion
            ctrl.wait_transfer_completion(last_trb_ptr)?;
        }
        
        ctrl.transfers_completed.fetch_add(1, Ordering::Relaxed);
        Ok(bytes_transferred)
    } else {
        Err("xHCI controller not initialized")
    }
}
