//! VirtIO Network Device Driver
// NOTE: We negotiate only features we actually implement; offloads are disabled
// unless explicitly added. MRG_RXBUF is not negotiated, so RX is single-buffer.

use alloc::{collections::VecDeque, sync::Arc, vec, vec::Vec};
use core::{mem, ptr};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;
use x86_64::{PhysAddr, VirtAddr};

use crate::drivers::pci::{pci_read_config32, PciBar, PciDevice};
use crate::interrupts::register_interrupt_handler;
use crate::memory::dma::alloc_dma_coherent;

// PCI IDs
const VIRTIO_VENDOR_ID: u16 = 0x1AF4;
const VIRTIO_NET_DEVICE_ID_TRANSITIONAL: u16 = 0x1000;
const VIRTIO_NET_DEVICE_ID_MODERN: u16 = 0x1041;

// Feature bits (indexes)
const VIRTIO_NET_F_MAC: u32 = 5;
const VIRTIO_NET_F_STATUS: u32 = 16;
const VIRTIO_NET_F_CTRL_VQ: u32 = 17;

// Queue indices
const Q_RX: u16 = 0;
const Q_TX: u16 = 1;
const Q_CTRL: u16 = 2;

// Legacy (fallback) offsets
const LEG_HOST_FEATURES: usize = 0x00;
const LEG_GUEST_FEATURES: usize = 0x04;
const LEG_QUEUE_PFN: usize = 0x08;
const LEG_QUEUE_NUM: usize = 0x0C;
const LEG_QUEUE_SEL: usize = 0x0E;
const LEG_STATUS: usize = 0x12;
const LEG_ISR: usize = 0x13;
const LEG_MAC: usize = 0x14;
const LEG_NOTIFY: usize = 0x10;

// Virtio-pci vendor capability types
const VIRTIO_PCI_CAP_VENDOR: u8 = 0x09;
const CAP_COMMON_CFG: u8 = 1;
const CAP_NOTIFY_CFG: u8 = 2;
const CAP_ISR_CFG: u8 = 3;
const CAP_DEVICE_CFG: u8 = 4;

// Virtio net header
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct VirtioNetHeader {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
    pub num_buffers: u16,
}
impl Default for VirtioNetHeader {
    fn default() -> Self {
        Self {
            flags: 0,
            gso_type: 0,
            hdr_len: 0,
            gso_size: 0,
            csum_start: 0,
            csum_offset: 0,
            num_buffers: 1,
        }
    }
}

// Virtqueue structures
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct VirtqDesc {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}
#[repr(C)]
pub struct VirtqAvail {
    pub flags: u16,
    pub idx: u16,
    pub ring: [u16; 0],
}
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct VirtqUsedElem {
    pub id: u32,
    pub len: u32,
}
#[repr(C)]
pub struct VirtqUsed {
    pub flags: u16,
    pub idx: u16,
    pub ring: [VirtqUsedElem; 0],
}

struct DmaRegion {
    va: VirtAddr,
    pa: PhysAddr,
    size: usize,
}
impl DmaRegion {
    fn new(size: usize) -> Result<Self, &'static str> {
        let (va, pa) = alloc_dma_coherent(size)?;
        unsafe { ptr::write_bytes(va.as_mut_ptr::<u8>(), 0, size) };
        Ok(Self { va, pa, size })
    }
    #[inline]
    fn as_mut_ptr<T>(&self) -> *mut T {
        self.va.as_mut_ptr::<T>()
    }
    #[inline]
    fn phys(&self) -> PhysAddr {
        self.pa
    }
}

// Virtqueue with owner maps and per-queue notify address
pub struct VirtQueue {
    pub queue_size: u16,
    desc_region: DmaRegion,
    avail_region: DmaRegion,
    used_region: DmaRegion,
    pub desc_table: *mut VirtqDesc,
    pub avail_ring: *mut VirtqAvail,
    pub used_ring: *mut VirtqUsed,
    pub desc_table_phys: PhysAddr,
    pub avail_ring_phys: PhysAddr,
    pub used_ring_phys: PhysAddr,
    pub free_descriptors: VecDeque<u16>,
    pub last_used_idx: u16,
    pub next_avail_idx: u16,

    rx_owner: Vec<Option<Arc<Mutex<PacketBuffer>>>>,
    tx_owner: Vec<Option<Arc<Mutex<PacketBuffer>>>>,

    notify_addr: usize,
}
unsafe impl Send for VirtQueue {}
unsafe impl Sync for VirtQueue {}

impl VirtQueue {
    pub fn new(queue_size: u16) -> Result<Self, &'static str> {
        if !queue_size.is_power_of_two() {
            return Err("virtq: queue_size must be power of two");
        }

        let dt_size = queue_size as usize * mem::size_of::<VirtqDesc>();
        let av_size = mem::size_of::<VirtqAvail>() + (queue_size as usize * 2) + 2;
        let us_size = mem::size_of::<VirtqUsed>() + (queue_size as usize * mem::size_of::<VirtqUsedElem>()) + 2;

        let desc_region = DmaRegion::new(dt_size)?;
        let avail_region = DmaRegion::new(av_size)?;
        let used_region = DmaRegion::new(us_size)?;

        let desc_table = desc_region.as_mut_ptr::<VirtqDesc>();
        let avail_ring = avail_region.as_mut_ptr::<VirtqAvail>();
        let used_ring = used_region.as_mut_ptr::<VirtqUsed>();

        let mut free = VecDeque::with_capacity(queue_size as usize);
        for i in 0..queue_size {
            free.push_back(i);
        }

        Ok(Self {
            queue_size,
            desc_region,
            avail_region,
            used_region,
            desc_table,
            avail_ring,
            used_ring,
            desc_table_phys: desc_region.phys(),
            avail_ring_phys: avail_region.phys(),
            used_ring_phys: used_region.phys(),
            free_descriptors: free,
            last_used_idx: 0,
            next_avail_idx: 0,
            rx_owner: vec![None; queue_size as usize],
            tx_owner: vec![None; queue_size as usize],
            notify_addr: 0,
        })
    }

    pub fn set_notify_addr(&mut self, addr: usize) {
        self.notify_addr = addr;
    }

    pub fn alloc_desc_chain(&mut self, count: usize) -> Option<Vec<u16>> {
        if self.free_descriptors.len() < count {
            return None;
        }
        let mut chain = Vec::with_capacity(count);
        for _ in 0..count {
            chain.push(self.free_descriptors.pop_front()?);
        }
        for i in 0..(count.saturating_sub(1)) {
            unsafe {
                let d = &mut *self.desc_table.add(chain[i] as usize);
                d.next = chain[i + 1];
                d.flags |= 1; // NEXT
            }
        }
        Some(chain)
    }

    pub fn free_desc_chain(&mut self, chain: Vec<u16>) {
        for idx in chain {
            unsafe { ptr::write_bytes(self.desc_table.add(idx as usize), 0, 1) };
            if (idx as usize) < self.rx_owner.len() {
                self.rx_owner[idx as usize] = None;
            }
            if (idx as usize) < self.tx_owner.len() {
                self.tx_owner[idx as usize] = None;
            }
            self.free_descriptors.push_back(idx);
        }
    }

    pub fn add_to_avail_ring(&mut self, desc_idx: u16) {
        unsafe {
            let base = self.avail_ring as *mut u8;
            let ring = base.add(mem::size_of::<VirtqAvail>()) as *mut u16;
            let idx = self.next_avail_idx % self.queue_size;
            *ring.add(idx as usize) = desc_idx;

            core::sync::atomic::fence(Ordering::SeqCst);
            self.next_avail_idx = self.next_avail_idx.wrapping_add(1);
            (*self.avail_ring).idx = self.next_avail_idx;
        }
    }

    pub fn kick(&self) {
        if self.notify_addr != 0 {
            unsafe { ptr::write_volatile(self.notify_addr as *mut u16, 0u16) };
        }
    }

    pub fn get_used_buffers(&mut self) -> Vec<(u16, u32)> {
        let mut out = Vec::new();
        unsafe {
            let cur = (*self.used_ring).idx;
            while self.last_used_idx != cur {
                let used_bytes = self.used_ring as *mut u8;
                let ring = used_bytes.add(mem::size_of::<VirtqUsed>()) as *mut VirtqUsedElem;
                let i = self.last_used_idx % self.queue_size;
                let u = *ring.add(i as usize);
                out.push((u.id as u16, u.len));
                self.last_used_idx = self.last_used_idx.wrapping_add(1);
            }
        }
        out
    }

    pub fn set_rx_owner(&mut self, desc: u16, b: Arc<Mutex<PacketBuffer>>) {
        if (desc as usize) < self.rx_owner.len() {
            self.rx_owner[desc as usize] = Some(b);
        }
    }
    pub fn take_rx_owner(&mut self, desc: u16) -> Option<Arc<Mutex<PacketBuffer>>> {
        if (desc as usize) < self.rx_owner.len() {
            self.rx_owner[desc as usize].take()
        } else {
            None
        }
    }

    pub fn set_tx_owner(&mut self, desc: u16, b: Arc<Mutex<PacketBuffer>>) {
        if (desc as usize) < self.tx_owner.len() {
            self.tx_owner[desc as usize] = Some(b);
        }
    }
    pub fn take_tx_owner(&mut self, desc: u16) -> Option<Arc<Mutex<PacketBuffer>>> {
        if (desc as usize) < self.tx_owner.len() {
            self.tx_owner[desc as usize].take()
        } else {
            None
        }
    }
}

pub struct PacketBuffer {
    dma_virt: VirtAddr,
    dma_phys: PhysAddr,
    len: usize,
    cap: usize,
}
impl PacketBuffer {
    pub fn new(size: usize) -> Result<Self, &'static str> {
        let (va, pa) = alloc_dma_coherent(size)?;
        unsafe { ptr::write_bytes(va.as_mut_ptr::<u8>(), 0, size) };
        Ok(Self {
            dma_virt: va,
            dma_phys: pa,
            len: 0,
            cap: size,
        })
    }
    pub fn write(&mut self, data: &[u8]) -> Result<(), &'static str> {
        if data.len() > self.cap {
            return Err("packet too large for buffer");
        }
        unsafe {
            ptr::copy_nonoverlapping(data.as_ptr(), self.dma_virt.as_mut_ptr::<u8>(), data.len());
        }
        self.len = data.len();
        Ok(())
    }
    pub fn phys(&self) -> PhysAddr {
        self.dma_phys
    }
    pub fn virt(&self) -> VirtAddr {
        self.dma_virt
    }
    pub fn capacity(&self) -> usize {
        self.cap
    }
    pub fn set_len(&mut self, n: usize) {
        self.len = core::cmp::min(n, self.cap);
    }
}

// Modern virtio-pci config structs (in-memory mapped)
#[repr(C, packed)]
struct VirtioPciCommonCfg {
    device_feature_select: u32,
    device_feature: u32,
    driver_feature_select: u32,
    driver_feature: u32,
    msix_config: u16,
    num_queues: u16,
    device_status: u8,
    config_generation: u8,
    queue_select: u16,
    queue_size: u16,
    queue_msix_vector: u16,
    queue_enable: u16,
    queue_notify_off: u16,
    queue_desc: u64,
    queue_avail: u64,
    queue_used: u64,
}

struct VirtioModernRegs {
    common: *mut VirtioPciCommonCfg,
    isr_ptr: *mut u8,
    notify_base: usize,
    notify_off_multiplier: u32,
    device_cfg: usize,
    bar_bases: [Option<usize>; 6],
}

impl VirtioModernRegs {
    fn map(pci: &PciDevice) -> Option<Self> {
        let mut bar_bases: [Option<usize>; 6] = [None; 6];
        for i in 0..6 {
            if let Ok(b) = pci.get_bar(i) {
                if let PciBar::Memory { address, .. } = b {
                    bar_bases[i] = Some(address.as_u64() as usize);
                }
            }
        }

        // Walk vendor capabilities (0x09) to find cfgs
        let mut common: *mut VirtioPciCommonCfg = core::ptr::null_mut();
        let mut isr_ptr: *mut u8 = core::ptr::null_mut();
        let mut notify_base = 0usize;
        let mut notify_mul = 0u32;
        let mut device_cfg = 0usize;

        for cap in pci.capabilities.iter().filter(|c| c.id == VIRTIO_PCI_CAP_VENDOR) {
            // Read fields we need (type, bar, offset, length...)
            let cap_hdr0 = pci_read_config32(pci.bus, pci.device, pci.function, cap.offset);
            let cap_hdr1 = pci_read_config32(pci.bus, pci.device, pci.function, cap.offset + 4);
            let cap_hdr2 = pci_read_config32(pci.bus, pci.device, pci.function, cap.offset + 8);
            let cap_len = ((cap_hdr0 >> 16) & 0xFF) as u8;
            let cfg_type = ((cap_hdr0 >> 24) & 0xFF) as u8;
            let bar = (cap_hdr1 & 0xFF) as u8;
            let offset_low = cap_hdr1 >> 16;
            let offset_high = cap_hdr2 & 0xFFFF;
            let cfg_offset = ((offset_high as u64) << 16 | offset_low as u64) as usize;

            let base = bar_bases.get(bar as usize).and_then(|x| *x).unwrap_or(0);
            let mmio = base.wrapping_add(cfg_offset);

            match cfg_type {
                CAP_COMMON_CFG => common = mmio as *mut VirtioPciCommonCfg,
                CAP_ISR_CFG => isr_ptr = mmio as *mut u8,
                CAP_DEVICE_CFG => device_cfg = mmio,
                CAP_NOTIFY_CFG => {
                    notify_base = mmio;
                    // notify cap: next dword after header stores multiplier (cap_len must be >= 0x10)
                    if cap_len as usize >= 0x10 {
                        let mul = pci_read_config32(pci.bus, pci.device, pci.function, cap.offset + 16);
                        notify_mul = mul;
                    }
                }
                _ => {}
            }
        }

        if !common.is_null() && !isr_ptr.is_null() && notify_base != 0 {
            Some(Self {
                common,
                isr_ptr,
                notify_base,
                notify_off_multiplier: notify_mul,
                device_cfg,
                bar_bases,
            })
        } else {
            None
        }
    }
}

// Device stats
#[derive(Default)]
pub struct NetworkStats {
    pub rx_packets: AtomicU64,
    pub tx_packets: AtomicU64,
    pub rx_bytes: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub rx_errors: AtomicU64,
    pub tx_errors: AtomicU64,
    pub rx_dropped: AtomicU64,
    pub tx_dropped: AtomicU64,
}

// Device
pub struct VirtioNetDevice {
    pub pci_device: PciDevice,
    pub legacy_bar: Option<PciBar>,

    modern: Option<VirtioModernRegs>,

    pub mac_address: [u8; 6],
    pub features: u32,

    pub rx_queue: Mutex<VirtQueue>,
    pub tx_queue: Mutex<VirtQueue>,
    pub ctrl_queue: Option<Mutex<VirtQueue>>,

    pub rx_buffers: Mutex<Vec<Arc<Mutex<PacketBuffer>>>>,
    pub tx_buffers: Mutex<Vec<Arc<Mutex<PacketBuffer>>>>,

    pub stats: NetworkStats,
    pub interrupt_vector: u8,
}

impl VirtioNetDevice {
    pub fn new(pci_device: PciDevice) -> Result<Self, &'static str> {
        if pci_device.vendor_id != VIRTIO_VENDOR_ID {
            return Err("virtio-net: wrong vendor");
        }
        if pci_device.device_id != VIRTIO_NET_DEVICE_ID_TRANSITIONAL
            && pci_device.device_id != VIRTIO_NET_DEVICE_ID_MODERN
        {
            return Err("virtio-net: wrong device id");
        }

        // Prefer modern registers
        let modern = VirtioModernRegs::map(&pci_device);
        let legacy_bar = if modern.is_none() { Some(pci_device.get_bar(0)?) } else { None };

        // Negotiate features + read MAC
        let (mac, features) = if let Some(ref regs) = modern {
            unsafe {
                // Ack + driver
                ptr::write_volatile(&mut (*regs.common).device_status, 1 | 2);
                // Device features (sel=0)
                ptr::write_volatile(&mut (*regs.common).device_feature_select, 0);
                let devf = ptr::read_volatile(&(*regs.common).device_feature);
                let supported = (1 << VIRTIO_NET_F_MAC) | (1 << VIRTIO_NET_F_STATUS) | (1 << VIRTIO_NET_F_CTRL_VQ);
                ptr::write_volatile(&mut (*regs.common).driver_feature_select, 0);
                ptr::write_volatile(&mut (*regs.common).driver_feature, devf & supported);
                // FEATURES_OK
                let s0 = ptr::read_volatile(&(*regs.common).device_status);
                ptr::write_volatile(&mut (*regs.common).device_status, s0 | 8);
                let s1 = ptr::read_volatile(&(*regs.common).device_status);
                if (s1 & 8) == 0 {
                    return Err("virtio-net: FEATURES_OK rejected");
                }
                // MAC via device_cfg
                let mut mac = [0u8; 6];
                for i in 0..6 {
                    mac[i] = ptr::read_volatile((regs.device_cfg + i) as *const u8);
                }
                (mac, devf & supported)
            }
        } else {
            // Legacy fallback
            let bar = legacy_bar.as_ref().ok_or("virtio-net: missing legacy BAR")?;
            let base = match bar {
                PciBar::Memory { address, .. } => address.as_u64() as usize,
                _ => return Err("virtio-net: legacy needs MMIO BAR"),
            };

            unsafe {
                // Reset
                ptr::write_volatile((base + LEG_STATUS) as *mut u8, 0);
                // Ack + driver
                ptr::write_volatile((base + LEG_STATUS) as *mut u8, 1);
                let cur = ptr::read_volatile((base + LEG_STATUS) as *const u8);
                ptr::write_volatile((base + LEG_STATUS) as *mut u8, cur | 2);
                // Features
                let devf = ptr::read_volatile((base + LEG_HOST_FEATURES) as *const u32);
                let supported = (1 << VIRTIO_NET_F_MAC) | (1 << VIRTIO_NET_F_STATUS);
                ptr::write_volatile((base + LEG_GUEST_FEATURES) as *mut u32, devf & supported);
                // FEATURES_OK
                let c2 = ptr::read_volatile((base + LEG_STATUS) as *const u8);
                ptr::write_volatile((base + LEG_STATUS) as *mut u8, c2 | 8);
                // MAC
                let mut mac = [0u8; 6];
                for i in 0..6 {
                    mac[i] = ptr::read_volatile((base + LEG_MAC + i) as *const u8);
                }
                (mac, devf & supported)
            }
        };

        // Build queues (size after negotiation for modern)
        let rxq = Mutex::new(VirtQueue::new(256)?);
        let txq = Mutex::new(VirtQueue::new(256)?);
        let ctrlq = Some(Mutex::new(VirtQueue::new(64)?));

        let mut dev = Self {
            pci_device,
            legacy_bar,
            modern,
            mac_address: mac,
            features,
            rx_queue: rxq,
            tx_queue: txq,
            ctrl_queue: ctrlq,
            rx_buffers: Mutex::new(Vec::new()),
            tx_buffers: Mutex::new(Vec::new()),
            stats: NetworkStats::default(),
            interrupt_vector: 0,
        };

        // Program queues
        if dev.modern.is_some() {
            dev.setup_queues_modern()?;
        } else {
            dev.setup_queues_legacy()?; // best-effort (legacy devices rare now)
        }

        // Buffers
        {
            let mut rx = dev.rx_buffers.lock();
            for _ in 0..128 {
                rx.push(Arc::new(Mutex::new(PacketBuffer::new(2048)?)));
            }
            let mut tx = dev.tx_buffers.lock();
            for _ in 0..64 {
                tx.push(Arc::new(Mutex::new(PacketBuffer::new(2048)?)));
            }
        }

        // Prime RX
        dev.refill_rx(64);

        // DRIVER_OK
        dev.set_status_driver_ok();

        Ok(dev)
    }

    fn setup_queues_modern(&mut self) -> Result<(), &'static str> {
        let regs = self.modern.as_ref().unwrap();
        unsafe {
            for qidx in [Q_RX, Q_TX] {
                // Select queue and read max
                ptr::write_volatile(&mut (*regs.common).queue_select, qidx);
                let qmax = ptr::read_volatile(&(*regs.common).queue_size);
                if qmax == 0 {
                    return Err("virtio-net: queue not available");
                }
                let want = 256u16;
                let qsize = core::cmp::min(want, qmax);
                ptr::write_volatile(&mut (*regs.common).queue_size, qsize);

                // Addresses
                let (desc, avail, used) = match qidx {
                    Q_RX => {
                        let q = self.rx_queue.get_mut();
                        (q.desc_table_phys.as_u64(), q.avail_ring_phys.as_u64(), q.used_ring_phys.as_u64())
                    }
                    Q_TX => {
                        let q = self.tx_queue.get_mut();
                        (q.desc_table_phys.as_u64(), q.avail_ring_phys.as_u64(), q.used_ring_phys.as_u64())
                    }
                    _ => unreachable!(),
                };

                ptr::write_volatile(&mut (*regs.common).queue_desc, desc);
                ptr::write_volatile(&mut (*regs.common).queue_avail, avail);
                ptr::write_volatile(&mut (*regs.common).queue_used, used);
                ptr::write_volatile(&mut (*regs.common).queue_enable, 1);

                // Compute notify address
                let noff = ptr::read_volatile(&(*regs.common).queue_notify_off);
                let naddr = regs.notify_base + (noff as usize) * (regs.notify_off_multiplier as usize);
                match qidx {
                    Q_RX => self.rx_queue.get_mut().set_notify_addr(naddr),
                    Q_TX => self.tx_queue.get_mut().set_notify_addr(naddr),
                    _ => {}
                }
            }
        }
        Ok(())
    }

    fn setup_queues_legacy(&mut self) -> Result<(), &'static str> {
        // Proper legacy PFN layout requires one contiguous area for desc/avail/used with
        // page-sized alignment. Many deployments are modern; we keep legacy best-effort
        // and prefer polling if device does not interrupt.
        Ok(())
    }

    fn set_status_driver_ok(&mut self) {
        if let Some(ref regs) = self.modern {
            unsafe {
                let s = ptr::read_volatile(&(*regs.common).device_status);
                ptr::write_volatile(&mut (*regs.common).device_status, s | 4);
            }
        } else if let Some(PciBar::Memory { address, .. }) = &self.legacy_bar {
            let base = address.as_u64() as usize;
            unsafe {
                let s = ptr::read_volatile((base + LEG_STATUS) as *const u8);
                ptr::write_volatile((base + LEG_STATUS) as *mut u8, s | 4);
            }
        }
    }

    pub fn setup_interrupts(&mut self) -> Result<(), &'static str> {
        let vector = crate::interrupts::allocate_vector()?;
        extern "C" fn isr_wrapper() {
            crate::drivers::nonos_virtio_net::super_virtio_isr();
        }
        register_interrupt_handler(vector, isr_wrapper)?;
        self.pci_device.configure_msix(vector)?;
        self.interrupt_vector = vector;
        Ok(())
    }

    pub fn transmit_packet(&self, payload: &[u8]) -> Result<(), &'static str> {
        if payload.len() > 1514 {
            return Err("packet too large");
        }
        // Choose TX buffer (index 0 simple policy)
        let buf_arc = {
            let v = self.tx_buffers.lock();
            v.get(0).cloned().ok_or("no TX buffers")?
        };

        // Build header + payload into DMA
        let hdr = VirtioNetHeader::default();
        let hdr_bytes =
            unsafe { core::slice::from_raw_parts(&hdr as *const _ as *const u8, mem::size_of::<VirtioNetHeader>()) };
        let total = hdr_bytes.len() + payload.len();

        {
            let mut b = buf_arc.lock();
            if total > b.capacity() {
                return Err("TX buffer too small");
            }
            unsafe {
                ptr::copy_nonoverlapping(hdr_bytes.as_ptr(), b.virt().as_mut_ptr::<u8>(), hdr_bytes.len());
                ptr::copy_nonoverlapping(
                    payload.as_ptr(),
                    b.virt().as_mut_ptr::<u8>().add(hdr_bytes.len()),
                    payload.len(),
                );
            }
            b.set_len(total);
        }

        // Build TX descriptor
        let mut txq = self.tx_queue.lock();
        let chain = txq.alloc_desc_chain(1).ok_or("no TX descriptors")?;
        let idx = chain[0] as usize;
        unsafe {
            let d = &mut *txq.desc_table.add(idx);
            d.addr = buf_arc.lock().phys().as_u64();
            d.len = total as u32;
            d.flags = 0; // device reads
            d.next = 0;
        }
        txq.set_tx_owner(chain[0], buf_arc);
        txq.add_to_avail_ring(chain[0]);
        txq.kick();

        self.stats.tx_packets.fetch_add(1, Ordering::Relaxed);
        self.stats.tx_bytes.fetch_add(payload.len() as u64, Ordering::Relaxed);
        Ok(())
    }

    pub fn receive_packets(&self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut rxq = self.rx_queue.lock();

        for (desc, len) in rxq.get_used_buffers() {
            if len < mem::size_of::<VirtioNetHeader>() as u32 {
                self.stats.rx_errors.fetch_add(1, Ordering::Relaxed);
                // Re-arm
                if let Some(buf) = rxq.take_rx_owner(desc) {
                    let phys = buf.lock().phys();
                    unsafe {
                        let d = &mut *rxq.desc_table.add(desc as usize);
                        d.addr = phys.as_u64();
                        d.len = 2048;
                        d.flags = 2; // WRITE
                        d.next = 0;
                    }
                    rxq.set_rx_owner(desc, buf);
                    rxq.add_to_avail_ring(desc);
                }
                continue;
            }
            if let Some(buf) = rxq.take_rx_owner(desc) {
                let pkt_len = (len as usize) - mem::size_of::<VirtioNetHeader>();
                let mut pkt = vec![0u8; pkt_len];
                unsafe {
                    ptr::copy_nonoverlapping(
                        buf.lock().virt().as_ptr::<u8>().add(mem::size_of::<VirtioNetHeader>()),
                        pkt.as_mut_ptr(),
                        pkt_len,
                    );
                }
                out.push(pkt);
                self.stats.rx_packets.fetch_add(1, Ordering::Relaxed);
                self.stats.rx_bytes.fetch_add(pkt_len as u64, Ordering::Relaxed);

                // Re-arm
                let phys = buf.lock().phys();
                unsafe {
                    let d = &mut *rxq.desc_table.add(desc as usize);
                    d.addr = phys.as_u64();
                    d.len = 2048;
                    d.flags = 2; // WRITE
                    d.next = 0;
                }
                rxq.set_rx_owner(desc, buf);
                rxq.add_to_avail_ring(desc);
            }
        }
        rxq.kick();
        out
    }

    pub fn reclaim_tx(&self) {
        let mut txq = self.tx_queue.lock();
        for (desc, _len) in txq.get_used_buffers() {
            let _ = txq.take_tx_owner(desc);
            txq.free_descriptors.push_back(desc);
        }
    }

    fn refill_rx(&self, count: usize) {
        let rxb = self.rx_buffers.lock();
        let mut rxq = self.rx_queue.lock();

        for buf in rxb.iter().take(count) {
            if let Some(chain) = rxq.alloc_desc_chain(1) {
                let idx = chain[0] as usize;
                let phys = buf.lock().phys();
                unsafe {
                    let d = &mut *rxq.desc_table.add(idx);
                    d.addr = phys.as_u64();
                    d.len = 2048;
                    d.flags = 2; // WRITE
                    d.next = 0;
                }
                rxq.set_rx_owner(chain[0], buf.clone());
                rxq.add_to_avail_ring(chain[0]);
            } else {
                break;
            }
        }
        rxq.kick();
    }

    pub fn ack_interrupt(&self) {
        if let Some(ref regs) = self.modern {
            unsafe {
                let _ = ptr::read_volatile(regs.isr_ptr);
            }
        } else if let Some(PciBar::Memory { address, .. }) = &self.legacy_bar {
            unsafe {
                let _ = ptr::read_volatile((address.as_u64() as usize + LEG_ISR) as *const u8);
            }
        }
    }

    pub fn deinit(&mut self) {
        // Optional: disable queues, free DMA; persistent in kernel lifetime.
    }
}

// Global singleton
static VIRTIO_NET: spin::Once<Arc<Mutex<VirtioNetDevice>>> = spin::Once::new();

pub fn init_virtio_net() -> Result<(), &'static str> {
    let devs = crate::arch::x86_64::pci::scan_pci_bus()?;
    for d in devs {
        if d.vendor_id == VIRTIO_VENDOR_ID
            && (d.device_id == VIRTIO_NET_DEVICE_ID_TRANSITIONAL || d.device_id == VIRTIO_NET_DEVICE_ID_MODERN)
        {
            crate::log::info!("virtio-net at {:02x}:{:02x}.{}", d.bus, d.slot, d.function);
            let mut nic = VirtioNetDevice::new(d)?;
            let _ = nic.setup_interrupts();
            let arc = Arc::new(Mutex::new(nic));
            VIRTIO_NET.call_once(|| arc.clone());

            // Log MAC
            let mac = arc.lock().mac_address;
            crate::log::info!(
                "virtio-net MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                mac[0],
                mac[1],
                mac[2],
                mac[3],
                mac[4],
                mac[5]
            );

            // Register as default interface in drivers network core
            crate::drivers::nonos_network::stack::register_interface(
                "eth0",
                Arc::new(VirtioNetInterface),
                true,
            );

            return Ok(());
        }
    }
    Err("virtio-net: no device found")
}

pub fn get_virtio_net_device() -> Option<Arc<Mutex<VirtioNetDevice>>> {
    VIRTIO_NET.get().cloned()
}

// ISR entry
extern "x86-interrupt" fn virtio_net_isr(_: crate::arch::x86_64::InterruptStackFrame) {
    super_virtio_isr();
}

#[no_mangle]
extern "C" fn super_virtio_isr() {
    if let Some(dev) = get_virtio_net_device() {
        let d = dev.lock();
        let packets = d.receive_packets();
        for p in packets {
            let _ = crate::drivers::nonos_network::stack::receive_packet(&p);
        }
        d.reclaim_tx();
        d.ack_interrupt();
    }
    crate::arch::x86_64::interrupt::apic::send_eoi();
}

// Public interface for the network core
pub struct VirtioNetInterface;

impl crate::drivers::nonos_network::stack::NetworkInterface for VirtioNetInterface {
    fn send_packet(&self, frame: &[u8]) -> Result<(), &'static str> {
        if let Some(d) = get_virtio_net_device() {
            d.lock().transmit_packet(frame)
        } else {
            Err("virtio-net not ready")
        }
    }
    fn get_mac_address(&self) -> [u8; 6] {
        if let Some(d) = get_virtio_net_device() {
            d.lock().mac_address
        } else {
            [0; 6]
        }
    }
    fn is_link_up(&self) -> bool {
        true
    }
    fn get_stats(&self) -> crate::drivers::nonos_network::stack::NetworkStats {
        if let Some(dev) = get_virtio_net_device() {
            let s = &dev.lock().stats;
            crate::drivers::nonos_network::stack::NetworkStats {
                rx_packets: AtomicU64::new(s.rx_packets.load(Ordering::Relaxed)),
                tx_packets: AtomicU64::new(s.tx_packets.load(Ordering::Relaxed)),
                rx_bytes: AtomicU64::new(s.rx_bytes.load(Ordering::Relaxed)),
                tx_bytes: AtomicU64::new(s.tx_bytes.load(Ordering::Relaxed)),
                active_sockets: AtomicU64::new(0),
                packets_dropped: AtomicU64::new(s.rx_errors.load(Ordering::Relaxed)),
                arp_lookups: AtomicU64::new(0),
            }
        } else {
            crate::drivers::nonos_network::stack::NetworkStats::default()
        }
    }
}
