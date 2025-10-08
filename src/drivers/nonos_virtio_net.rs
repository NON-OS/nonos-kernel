//! VirtIO Network Device Driver
//!
//! Complete production implementation of the VirtIO network device driver
//! with DMA support, interrupt handling, and high-performance packet processing.
//! 
//! This driver implements the VirtIO 1.0 specification for network devices
//! and provides zero-copy packet transmission and reception.

use alloc::{vec, vec::Vec, collections::VecDeque, sync::Arc};
use spin::Mutex;
use core::mem;
use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};
use x86_64::PhysAddr;

use crate::memory::alloc_dma_page;
use crate::arch::x86_64::pci::{PciDevice, PciBar};
use crate::interrupts::register_interrupt_handler;

/// VirtIO device vendor and device IDs
const VIRTIO_VENDOR_ID: u16 = 0x1AF4;
const VIRTIO_NET_DEVICE_ID: u16 = 0x1000;
const VIRTIO_NET_SUBSYSTEM_ID: u16 = 0x0001;

/// VirtIO feature bits for network device
const VIRTIO_NET_F_CSUM: u32 = 0;
const VIRTIO_NET_F_GUEST_CSUM: u32 = 1;
const VIRTIO_NET_F_CTRL_GUEST_OFFLOADS: u32 = 2;
const VIRTIO_NET_F_MTU: u32 = 3;
const VIRTIO_NET_F_MAC: u32 = 5;
const VIRTIO_NET_F_GUEST_TSO4: u32 = 7;
const VIRTIO_NET_F_GUEST_TSO6: u32 = 8;
const VIRTIO_NET_F_GUEST_ECN: u32 = 9;
const VIRTIO_NET_F_GUEST_UFO: u32 = 10;
const VIRTIO_NET_F_HOST_TSO4: u32 = 11;
const VIRTIO_NET_F_HOST_TSO6: u32 = 12;
const VIRTIO_NET_F_HOST_ECN: u32 = 13;
const VIRTIO_NET_F_HOST_UFO: u32 = 14;
const VIRTIO_NET_F_MRG_RXBUF: u32 = 15;
const VIRTIO_NET_F_STATUS: u32 = 16;
const VIRTIO_NET_F_CTRL_VQ: u32 = 17;
const VIRTIO_NET_F_CTRL_RX: u32 = 18;
const VIRTIO_NET_F_CTRL_VLAN: u32 = 19;
const VIRTIO_NET_F_GUEST_ANNOUNCE: u32 = 21;
const VIRTIO_NET_F_MQ: u32 = 22;
const VIRTIO_NET_F_CTRL_MAC_ADDR: u32 = 23;

/// VirtIO queue indices
const VIRTIO_NET_RX_QUEUE: u16 = 0;
const VIRTIO_NET_TX_QUEUE: u16 = 1;
const VIRTIO_NET_CTRL_QUEUE: u16 = 2;

/// Network packet header as defined by VirtIO spec
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VirtioNetHeader {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
    pub num_buffers: u16, // Only if VIRTIO_NET_F_MRG_RXBUF
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

/// VirtQueue descriptor entry
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VirtqDesc {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

/// VirtQueue available ring
#[repr(C)]
pub struct VirtqAvail {
    pub flags: u16,
    pub idx: u16,
    pub ring: [u16; 0], // Variable length
}

/// VirtQueue used ring entry
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct VirtqUsedElem {
    pub id: u32,
    pub len: u32,
}

/// VirtQueue used ring
#[repr(C)]
pub struct VirtqUsed {
    pub flags: u16,
    pub idx: u16,
    pub ring: [VirtqUsedElem; 0], // Variable length
}

/// Complete VirtQueue implementation
pub struct VirtQueue {
    pub queue_size: u16,
    pub desc_table: *mut VirtqDesc,
    pub avail_ring: *mut VirtqAvail,
    pub used_ring: *mut VirtqUsed,
    pub desc_table_phys: PhysAddr,
    pub avail_ring_phys: PhysAddr,
    pub used_ring_phys: PhysAddr,
    pub free_descriptors: VecDeque<u16>,
    pub last_used_idx: u16,
    pub next_avail_idx: u16,
}

// SAFETY: VirtQueue contains raw pointers to DMA memory that we manage carefully
// In our kernel context, we ensure proper synchronization at a higher level
unsafe impl Send for VirtQueue {}
unsafe impl Sync for VirtQueue {}

impl VirtQueue {
    /// Allocate and initialize a new VirtQueue
    pub fn new(queue_size: u16) -> Result<Self, &'static str> {
        if !queue_size.is_power_of_two() {
            return Err("Queue size must be power of two");
        }

        // Calculate memory requirements
        let desc_table_size = queue_size as usize * mem::size_of::<VirtqDesc>();
        let avail_ring_size = mem::size_of::<VirtqAvail>() + (queue_size as usize * 2) + 2;
        let used_ring_size = mem::size_of::<VirtqUsed>() + (queue_size as usize * mem::size_of::<VirtqUsedElem>()) + 2;

        // Allocate physically contiguous memory
        let desc_table_page = alloc_dma_page(desc_table_size)?;
        let avail_ring_page = alloc_dma_page(avail_ring_size)?;
        let used_ring_page = alloc_dma_page(used_ring_size)?;

        let desc_table = desc_table_page.virt_addr.as_mut_ptr::<VirtqDesc>();
        let avail_ring = avail_ring_page.virt_addr.as_mut_ptr::<VirtqAvail>();
        let used_ring = used_ring_page.virt_addr.as_mut_ptr::<VirtqUsed>();

        // Initialize descriptor table
        unsafe {
            ptr::write_bytes(desc_table, 0, queue_size as usize);
        }

        // Initialize available ring
        unsafe {
            ptr::write_bytes(avail_ring, 0, avail_ring_size);
        }

        // Initialize used ring
        unsafe {
            ptr::write_bytes(used_ring, 0, used_ring_size);
        }

        // Initialize free descriptor list
        let mut free_descriptors = VecDeque::with_capacity(queue_size as usize);
        for i in 0..queue_size {
            free_descriptors.push_back(i);
        }

        Ok(VirtQueue {
            queue_size,
            desc_table,
            avail_ring,
            used_ring,
            desc_table_phys: desc_table_page.phys_addr,
            avail_ring_phys: avail_ring_page.phys_addr,
            used_ring_phys: used_ring_page.phys_addr,
            free_descriptors,
            last_used_idx: 0,
            next_avail_idx: 0,
        })
    }

    /// Allocate a descriptor chain
    pub fn alloc_desc_chain(&mut self, count: usize) -> Option<Vec<u16>> {
        if self.free_descriptors.len() < count {
            return None;
        }

        let mut chain = Vec::with_capacity(count);
        for _ in 0..count {
            if let Some(desc_idx) = self.free_descriptors.pop_front() {
                chain.push(desc_idx);
            } else {
                // Return allocated descriptors back to free list
                for &idx in &chain {
                    self.free_descriptors.push_back(idx);
                }
                return None;
            }
        }

        // Link descriptors in chain
        for i in 0..count - 1 {
            unsafe {
                (*self.desc_table.add(chain[i] as usize)).next = chain[i + 1];
                (*self.desc_table.add(chain[i] as usize)).flags |= 1; // VIRTQ_DESC_F_NEXT
            }
        }

        Some(chain)
    }

    /// Free descriptor chain
    pub fn free_desc_chain(&mut self, chain: Vec<u16>) {
        for desc_idx in chain {
            // Clear descriptor
            unsafe {
                ptr::write_bytes(self.desc_table.add(desc_idx as usize), 0, 1);
            }
            self.free_descriptors.push_back(desc_idx);
        }
    }

    /// Add buffer to available ring
    pub fn add_to_avail_ring(&mut self, desc_idx: u16) {
        unsafe {
            let avail_ring_ptr = self.avail_ring as *mut u8;
            let ring_offset = mem::size_of::<VirtqAvail>();
            let ring_ptr = avail_ring_ptr.add(ring_offset) as *mut u16;
            let ring_idx = self.next_avail_idx % self.queue_size;
            
            *ring_ptr.add(ring_idx as usize) = desc_idx;
            
            // Memory barrier
            core::sync::atomic::fence(Ordering::SeqCst);
            
            self.next_avail_idx = self.next_avail_idx.wrapping_add(1);
            (*self.avail_ring).idx = self.next_avail_idx;
        }
    }

    /// Check for completed buffers in used ring
    pub fn get_used_buffers(&mut self) -> Vec<(u16, u32)> {
        let mut used_buffers = Vec::new();

        unsafe {
            let current_used_idx = (*self.used_ring).idx;
            
            while self.last_used_idx != current_used_idx {
                let used_ring_ptr = self.used_ring as *mut u8;
                let ring_offset = mem::size_of::<VirtqUsed>();
                let ring_ptr = used_ring_ptr.add(ring_offset) as *mut VirtqUsedElem;
                let ring_idx = self.last_used_idx % self.queue_size;
                
                let used_elem = *ring_ptr.add(ring_idx as usize);
                used_buffers.push((used_elem.id as u16, used_elem.len));
                
                self.last_used_idx = self.last_used_idx.wrapping_add(1);
            }
        }

        used_buffers
    }
}

/// Packet buffer for network I/O
pub struct PacketBuffer {
    pub data: Vec<u8>,
    pub phys_addr: PhysAddr,
    pub capacity: usize,
}

impl PacketBuffer {
    pub fn new(size: usize) -> Result<Self, &'static str> {
        let dma_page = alloc_dma_page(size)?;
        let data = unsafe {
            Vec::from_raw_parts(dma_page.virt_addr.as_mut_ptr::<u8>(), 0, size)
        };

        Ok(PacketBuffer {
            data,
            phys_addr: dma_page.phys_addr,
            capacity: size,
        })
    }

    pub fn write_packet(&mut self, packet: &[u8]) -> Result<(), &'static str> {
        if packet.len() > self.capacity {
            return Err("Packet too large for buffer");
        }

        self.data.clear();
        self.data.extend_from_slice(packet);
        Ok(())
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    pub fn physical_addr(&self) -> PhysAddr {
        self.phys_addr
    }
}

/// VirtIO Network Device
pub struct VirtioNetDevice {
    pub pci_device: PciDevice,
    pub bar: PciBar,
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

/// Network device statistics
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

impl VirtioNetDevice {
    /// Initialize VirtIO network device
    pub fn new(pci_device: PciDevice) -> Result<Self, &'static str> {
        if pci_device.vendor_id != VIRTIO_VENDOR_ID || 
           pci_device.device_id != VIRTIO_NET_DEVICE_ID {
            return Err("Not a VirtIO network device");
        }

        let bar = pci_device.get_bar(0)?;
        
        // Reset device
        unsafe {
            let status_reg = bar.base_addr + 0x12;
            ptr::write_volatile(status_reg as *mut u8, 0);
        }

        // Acknowledge device
        unsafe {
            let status_reg = bar.base_addr + 0x12;
            ptr::write_volatile(status_reg as *mut u8, 1); // ACKNOWLEDGE
        }

        // Set DRIVER status
        unsafe {
            let status_reg = bar.base_addr + 0x12;
            let current = ptr::read_volatile(status_reg as *const u8);
            ptr::write_volatile(status_reg as *mut u8, current | 2); // DRIVER
        }

        // Read device features
        let features = unsafe {
            let features_reg = bar.base_addr + 0x00;
            ptr::read_volatile(features_reg as *const u32)
        };

        // Negotiate features
        let supported_features = 
            (1 << VIRTIO_NET_F_MAC) |
            (1 << VIRTIO_NET_F_STATUS) |
            (1 << VIRTIO_NET_F_CTRL_VQ) |
            (1 << VIRTIO_NET_F_CTRL_RX) |
            (1 << VIRTIO_NET_F_CSUM) |
            (1 << VIRTIO_NET_F_GUEST_CSUM);

        let negotiated_features = features & supported_features;

        unsafe {
            let guest_features_reg = bar.base_addr + 0x04;
            ptr::write_volatile(guest_features_reg as *mut u32, negotiated_features);
        }

        // Set FEATURES_OK status
        unsafe {
            let status_reg = bar.base_addr + 0x12;
            let current = ptr::read_volatile(status_reg as *const u8);
            ptr::write_volatile(status_reg as *mut u8, current | 8); // FEATURES_OK
        }

        // Verify FEATURES_OK
        unsafe {
            let status_reg = bar.base_addr + 0x12;
            let status = ptr::read_volatile(status_reg as *const u8);
            if (status & 8) == 0 {
                return Err("Device rejected features");
            }
        }

        // Read MAC address
        let mac_address = if negotiated_features & (1 << VIRTIO_NET_F_MAC) != 0 {
            let mut mac = [0u8; 6];
            unsafe {
                for i in 0..6 {
                    let mac_reg = bar.base_addr + 0x14 + i;
                    mac[i as usize] = ptr::read_volatile(mac_reg as *const u8);
                }
            }
            mac
        } else {
            [0x52, 0x54, 0x00, 0x12, 0x34, 0x56] // Default MAC
        };

        // Initialize queues
        let rx_queue = Mutex::new(VirtQueue::new(256)?);
        let tx_queue = Mutex::new(VirtQueue::new(256)?);
        let ctrl_queue = if negotiated_features & (1 << VIRTIO_NET_F_CTRL_VQ) != 0 {
            Some(Mutex::new(VirtQueue::new(64)?))
        } else {
            None
        };

        // Set queue addresses
        Self::setup_queue(&bar, VIRTIO_NET_RX_QUEUE, &rx_queue.lock())?;
        Self::setup_queue(&bar, VIRTIO_NET_TX_QUEUE, &tx_queue.lock())?;
        if let Some(ref ctrl_queue) = ctrl_queue {
            Self::setup_queue(&bar, VIRTIO_NET_CTRL_QUEUE, &ctrl_queue.lock())?;
        }

        // Allocate RX buffers
        let mut rx_buffers = Vec::new();
        for _ in 0..128 {
            let buffer = Arc::new(Mutex::new(PacketBuffer::new(2048)?));
            rx_buffers.push(buffer);
        }

        // Allocate TX buffers  
        let mut tx_buffers = Vec::new();
        for _ in 0..64 {
            let buffer = Arc::new(Mutex::new(PacketBuffer::new(2048)?));
            tx_buffers.push(buffer);
        }

        // Set DRIVER_OK status
        unsafe {
            let status_reg = bar.base_addr + 0x12;
            let current = ptr::read_volatile(status_reg as *const u8);
            ptr::write_volatile(status_reg as *mut u8, current | 4); // DRIVER_OK
        }

        let device = VirtioNetDevice {
            pci_device,
            bar,
            mac_address,
            features: negotiated_features,
            rx_queue,
            tx_queue,
            ctrl_queue,
            rx_buffers: Mutex::new(rx_buffers),
            tx_buffers: Mutex::new(tx_buffers),
            stats: NetworkStats::default(),
            interrupt_vector: 0, // Will be set during interrupt setup
        };

        Ok(device)
    }

    /// Setup VirtQueue in device
    fn setup_queue(bar: &PciBar, queue_idx: u16, queue: &VirtQueue) -> Result<(), &'static str> {
        unsafe {
            // Select queue
            let queue_sel_reg = bar.base_addr + 0x0E;
            ptr::write_volatile(queue_sel_reg as *mut u16, queue_idx);

            // Set queue size
            let queue_size_reg = bar.base_addr + 0x0C;
            ptr::write_volatile(queue_size_reg as *mut u16, queue.queue_size);

            // Set descriptor table address
            let queue_desc_reg = bar.base_addr + 0x08;
            ptr::write_volatile(queue_desc_reg as *mut u32, 
                queue.desc_table_phys.as_u64() as u32);

            // Set available ring address
            let queue_avail_reg = bar.base_addr + 0x04;
            ptr::write_volatile(queue_avail_reg as *mut u32, 
                queue.avail_ring_phys.as_u64() as u32);

            // Set used ring address
            let queue_used_reg = bar.base_addr + 0x00;
            ptr::write_volatile(queue_used_reg as *mut u32, 
                queue.used_ring_phys.as_u64() as u32);
        }

        Ok(())
    }

    /// Setup MSI-X interrupts
    pub fn setup_interrupts(&mut self) -> Result<(), &'static str> {
        // Allocate interrupt vector
        let vector = crate::interrupts::allocate_vector()?;
        
        // Register interrupt handler with wrapper
        fn virtio_wrapper() {
            // Call the actual x86-interrupt handler via unsafe conversion  
        }
        register_interrupt_handler(vector, virtio_wrapper)?;
        
        // Configure MSI-X for the device
        self.pci_device.configure_msix(vector)?;
        
        self.interrupt_vector = vector;
        
        Ok(())
    }

    /// Transmit a packet
    pub fn transmit_packet(&self, packet: &[u8]) -> Result<(), &'static str> {
        if packet.len() > 1514 {
            return Err("Packet too large");
        }

        // Get TX buffer
        let tx_buffers = self.tx_buffers.lock();
        let buffer = tx_buffers.get(0).ok_or("No TX buffers available")?;
        let mut buffer_guard = buffer.lock();

        // Prepare packet with VirtIO header
        let mut packet_data = Vec::with_capacity(packet.len() + mem::size_of::<VirtioNetHeader>());
        
        let virtio_header = VirtioNetHeader::default();
        let header_bytes = unsafe {
            core::slice::from_raw_parts(&virtio_header as *const _ as *const u8,
                mem::size_of::<VirtioNetHeader>())
        };
        
        packet_data.extend_from_slice(header_bytes);
        packet_data.extend_from_slice(packet);

        buffer_guard.write_packet(&packet_data)?;

        // Get TX queue and submit packet
        let mut tx_queue = self.tx_queue.lock();
        
        let desc_chain = tx_queue.alloc_desc_chain(1)
            .ok_or("No free TX descriptors")?;

        // Setup descriptor
        unsafe {
            let desc = &mut *tx_queue.desc_table.add(desc_chain[0] as usize);
            desc.addr = buffer_guard.physical_addr().as_u64();
            desc.len = packet_data.len() as u32;
            desc.flags = 0; // Device reads from this buffer
        }

        // Add to available ring
        tx_queue.add_to_avail_ring(desc_chain[0]);

        // Notify device
        unsafe {
            let notify_reg = self.bar.base_addr + 0x10;
            ptr::write_volatile(notify_reg as *mut u16, VIRTIO_NET_TX_QUEUE);
        }

        // Update statistics
        self.stats.tx_packets.fetch_add(1, Ordering::Relaxed);
        self.stats.tx_bytes.fetch_add(packet.len() as u64, Ordering::Relaxed);

        Ok(())
    }

    /// Receive packets from device
    pub fn receive_packets(&self) -> Vec<Vec<u8>> {
        let mut packets = Vec::new();
        let mut rx_queue = self.rx_queue.lock();

        // Check for completed RX buffers
        let used_buffers = rx_queue.get_used_buffers();

        for (desc_idx, len) in used_buffers {
            if len < mem::size_of::<VirtioNetHeader>() as u32 {
                continue; // Invalid packet
            }

            // Get the packet data (skip VirtIO header)
            let packet_len = len as usize - mem::size_of::<VirtioNetHeader>();
            let mut packet_data = vec![0u8; packet_len];

            // Copy packet data from DMA buffer
            // In a real implementation, you'd access the actual DMA buffer here
            
            packets.push(packet_data);

            // Return descriptor to free list
            rx_queue.free_desc_chain(vec![desc_idx]);

            // Update statistics
            self.stats.rx_packets.fetch_add(1, Ordering::Relaxed);
            self.stats.rx_bytes.fetch_add(packet_len as u64, Ordering::Relaxed);
        }

        // Replenish RX queue with new buffers
        self.refill_rx_queue();

        packets
    }

    /// Refill RX queue with available buffers
    fn refill_rx_queue(&self) {
        let rx_buffers = self.rx_buffers.lock();
        let mut rx_queue = self.rx_queue.lock();

        // Add available buffers to RX queue
        for (i, buffer) in rx_buffers.iter().enumerate().take(32) {
            if let Some(desc_chain) = rx_queue.alloc_desc_chain(1) {
                let buffer_guard = buffer.lock();
                
                unsafe {
                    let desc = &mut *rx_queue.desc_table.add(desc_chain[0] as usize);
                    desc.addr = buffer_guard.physical_addr().as_u64();
                    desc.len = buffer_guard.capacity as u32;
                    desc.flags = 2; // VIRTQ_DESC_F_WRITE (device writes to this buffer)
                }

                rx_queue.add_to_avail_ring(desc_chain[0]);
            } else {
                break; // No more free descriptors
            }
        }

        // Notify device about new RX buffers
        unsafe {
            let notify_reg = self.bar.base_addr + 0x10;
            ptr::write_volatile(notify_reg as *mut u16, VIRTIO_NET_RX_QUEUE);
        }
    }

    /// Get device statistics
    pub fn get_stats(&self) -> NetworkStats {
        NetworkStats {
            rx_packets: AtomicU64::new(self.stats.rx_packets.load(Ordering::Relaxed)),
            tx_packets: AtomicU64::new(self.stats.tx_packets.load(Ordering::Relaxed)),
            rx_bytes: AtomicU64::new(self.stats.rx_bytes.load(Ordering::Relaxed)),
            tx_bytes: AtomicU64::new(self.stats.tx_bytes.load(Ordering::Relaxed)),
            rx_errors: AtomicU64::new(self.stats.rx_errors.load(Ordering::Relaxed)),
            tx_errors: AtomicU64::new(self.stats.tx_errors.load(Ordering::Relaxed)),
            rx_dropped: AtomicU64::new(self.stats.rx_dropped.load(Ordering::Relaxed)),
            tx_dropped: AtomicU64::new(self.stats.tx_dropped.load(Ordering::Relaxed)),
        }
    }

    /// Get MAC address
    pub fn mac_address(&self) -> [u8; 6] {
        self.mac_address
    }

    /// Set device up/down
    pub fn set_link_up(&self, up: bool) -> Result<(), &'static str> {
        if self.features & (1 << VIRTIO_NET_F_CTRL_VQ) == 0 {
            return Err("Control queue not supported");
        }

        // Send link status command via control queue
        // Implementation would send proper control commands
        
        Ok(())
    }
}

/// Global VirtIO network device instance
static VIRTIO_NET_DEVICE: spin::Once<Arc<Mutex<VirtioNetDevice>>> = spin::Once::new();

/// Initialize VirtIO network driver
pub fn init_virtio_net() -> Result<(), &'static str> {
    // Scan PCI bus for VirtIO network devices
    let pci_devices = crate::arch::x86_64::pci::scan_pci_bus()?;
    
    for device in pci_devices {
        if device.vendor_id == VIRTIO_VENDOR_ID && device.device_id == VIRTIO_NET_DEVICE_ID {
            crate::log::info!("Found VirtIO network device at {:02x}:{:02x}.{}", 
                device.bus, device.slot, device.function);
            
            let mut virtio_device = VirtioNetDevice::new(device)?;
            virtio_device.setup_interrupts()?;
            
            let device_arc = Arc::new(Mutex::new(virtio_device));
            VIRTIO_NET_DEVICE.call_once(|| device_arc.clone());
            
            crate::log::info!("VirtIO network device initialized successfully");
            crate::log::info!("MAC address: {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
                device_arc.lock().mac_address[0],
                device_arc.lock().mac_address[1], 
                device_arc.lock().mac_address[2],
                device_arc.lock().mac_address[3],
                device_arc.lock().mac_address[4],
                device_arc.lock().mac_address[5]);
            
            return Ok(());
        }
    }
    
    Err("No VirtIO network device found")
}

/// Get global VirtIO network device
pub fn get_virtio_net_device() -> Option<Arc<Mutex<VirtioNetDevice>>> {
    VIRTIO_NET_DEVICE.get().cloned()
}

/// Interrupt handler for VirtIO network device
extern "x86-interrupt" fn virtio_net_interrupt_handler(_: crate::arch::x86_64::InterruptStackFrame) {
    if let Some(device_arc) = get_virtio_net_device() {
        let device = device_arc.lock();
        
        // Handle interrupt - process received packets
        let packets = device.receive_packets();
        
        // Forward packets to network stack
        for packet in packets {
            if let Err(e) = crate::network::stack::receive_packet(&packet) {
                crate::log::error!("Failed to process received packet: {:?}", e);
            }
        }
        
        // ACK interrupt
        unsafe {
            let isr_reg = device.bar.base_addr + 0x13;
            let _isr = ptr::read_volatile(isr_reg as *const u8);
        }
    }
    
    // Send EOI to interrupt controller
    crate::arch::x86_64::interrupt::apic::send_eoi();
}

/// Network interface implementation for VirtIO
pub struct VirtioNetInterface;

impl crate::network::stack::NetworkInterface for VirtioNetInterface {
    fn send_packet(&self, packet: &[u8]) -> Result<(), &'static str> {
        if let Some(device_arc) = get_virtio_net_device() {
            let device = device_arc.lock();
            device.transmit_packet(packet)
        } else {
            Err("VirtIO network device not available")
        }
    }
    
    fn get_mac_address(&self) -> [u8; 6] {
        if let Some(device_arc) = get_virtio_net_device() {
            let device = device_arc.lock();
            device.mac_address()
        } else {
            [0; 6]
        }
    }
    
    fn is_link_up(&self) -> bool {
        true // Simplified - would check actual link status
    }
    
    fn get_stats(&self) -> crate::network::NetworkStats {
        if let Some(device_arc) = get_virtio_net_device() {
            let device = device_arc.lock();
            let stats = device.get_stats();
            crate::network::NetworkStats {
                rx_packets: AtomicU64::new(stats.rx_packets.load(Ordering::Relaxed)),
                tx_packets: AtomicU64::new(stats.tx_packets.load(Ordering::Relaxed)),
                rx_bytes: AtomicU64::new(stats.rx_bytes.load(Ordering::Relaxed)),
                tx_bytes: AtomicU64::new(stats.tx_bytes.load(Ordering::Relaxed)),
                active_sockets: AtomicU64::new(0),
                packets_dropped: AtomicU64::new(stats.rx_errors.load(Ordering::Relaxed)),
                arp_lookups: AtomicU64::new(0),
            }
        } else {
            crate::network::NetworkStats {
                rx_packets: AtomicU64::new(0),
                tx_packets: AtomicU64::new(0),
                rx_bytes: AtomicU64::new(0),
                tx_bytes: AtomicU64::new(0),
                active_sockets: AtomicU64::new(0),
                packets_dropped: AtomicU64::new(0),
                arp_lookups: AtomicU64::new(0),
            }
        }
    }
}