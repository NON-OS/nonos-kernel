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

use core::ptr;
use core::sync::atomic::Ordering;

const QUEUE_SIZE: u16 = 16;
const BUFFER_SIZE: usize = 4096;
const VIRTQ_DESC_F_WRITE: u16 = 2;

/// VirtIO legacy virtqueue layout (VirtIO 1.0 s2.6.2):
///   desc table  @ offset 0        : 16 x 16 = 256 bytes
///   avail ring  @ offset 256      : 4 + 2x16 + 2 = 38 bytes (2-byte aligned)
///   used ring   @ offset 4096     : 4 + 8x16 + 2 = 134 bytes (page-aligned)
///   Total: 2 pages (8192 bytes)
const DESC_OFFSET: usize = 0;
const AVAIL_OFFSET: usize = 256;
const USED_OFFSET: usize = 4096;
const VQ_REGION_SIZE: usize = 8192;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct VirtqDesc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

#[repr(C)]
struct VirtqAvail {
    flags: u16,
    idx: u16,
    ring: [u16; QUEUE_SIZE as usize],
    _used_event: u16,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct VirtqUsedElem {
    _id: u32,
    len: u32,
}

#[repr(C)]
struct VirtqUsed {
    _flags: u16,
    idx: u16,
    ring: [VirtqUsedElem; QUEUE_SIZE as usize],
    _avail_event: u16,
}

// ============================================================================
// Static DMA buffers -- page-aligned, identity-mapped by UEFI boot path
//
// SAFETY rationale: The UEFI bootloader loads the kernel as a PE/ELF image
// into physical RAM and sets up 1:1 identity mapping. Static arrays in BSS
// therefore have virtual addresses == physical addresses, which is required
// for DMA. The E1000 driver uses the same pattern successfully.
// ============================================================================

/// Virtqueue region: contiguous, page-aligned, contains desc + avail + used.
#[repr(C, align(4096))]
struct VirtqueueRegionBuf([u8; VQ_REGION_SIZE]);

/// Data buffer: page-aligned, device writes random bytes here.
#[repr(C, align(4096))]
struct DataBuf([u8; BUFFER_SIZE]);

static mut VQ_REGION: VirtqueueRegionBuf = VirtqueueRegionBuf([0u8; VQ_REGION_SIZE]);
static mut DATA_BUF: DataBuf = DataBuf([0u8; BUFFER_SIZE]);

pub(super) struct RngQueue {
    vq_base: usize,
    buf_base: usize,
    last_used_idx: u16,
    next_avail_idx: u16,
    pending_len: usize,
    notify_port: u16,
    notify_mmio: u64,
}

// SAFETY: RngQueue references static buffers that are only accessed
// through the Mutex<Option<VirtioRngDevice>> in mod.rs.
unsafe impl Send for RngQueue {}
unsafe impl Sync for RngQueue {}

impl RngQueue {
    pub(super) fn new() -> Result<Self, &'static str> {
        // Take the address of the static buffers. These are identity-mapped
        // in the UEFI boot path, so virt addr == phys addr.
        // The Mutex in mod.rs ensures single-accessor semantics.
        let vq_base = ptr::addr_of!(VQ_REGION) as usize;
        let buf_base = ptr::addr_of!(DATA_BUF) as usize;

        // Verify page alignment at runtime
        if vq_base & 0xFFF != 0 {
            return Err("virtio-rng: VQ region not page-aligned");
        }
        if buf_base & 0xFFF != 0 {
            return Err("virtio-rng: data buffer not page-aligned");
        }

        // SAFETY: Zero the static regions before use. We own these exclusively
        // via the Mutex guard.
        unsafe {
            ptr::write_bytes(vq_base as *mut u8, 0, VQ_REGION_SIZE);
            ptr::write_bytes(buf_base as *mut u8, 0, BUFFER_SIZE);
        }

        Ok(Self {
            vq_base,
            buf_base,
            last_used_idx: 0,
            next_avail_idx: 0,
            pending_len: 0,
            notify_port: 0,
            notify_mmio: 0,
        })
    }

    /// Physical address of the virtqueue region base for legacy PFN programming.
    /// In identity-mapped UEFI boot, this equals the virtual address.
    pub(super) fn desc_table_phys(&self) -> u64 {
        self.vq_base as u64
    }

    pub(super) fn set_notify_addr(&mut self, port: u16) {
        self.notify_port = port;
    }

    pub(super) fn set_notify_mmio(&mut self, addr: u64) {
        self.notify_mmio = addr;
    }

    #[inline]
    fn desc_ptr(&self) -> *mut VirtqDesc {
        (self.vq_base + DESC_OFFSET) as *mut VirtqDesc
    }

    #[inline]
    fn avail_ptr(&self) -> *mut VirtqAvail {
        (self.vq_base + AVAIL_OFFSET) as *mut VirtqAvail
    }

    #[inline]
    fn used_ptr(&self) -> *mut VirtqUsed {
        (self.vq_base + USED_OFFSET) as *mut VirtqUsed
    }

    pub(super) fn request_random(&mut self, len: usize) -> Result<(), &'static str> {
        let len = len.min(BUFFER_SIZE);
        self.pending_len = len;

        // SAFETY: desc_ptr() / avail_ptr() point into our exclusively-owned
        // static VQ_REGION. buf_base points into our static DATA_BUF.
        // The Mutex in mod.rs guarantees single-accessor semantics.
        unsafe {
            ptr::write_bytes(self.buf_base as *mut u8, 0, BUFFER_SIZE);

            let desc = &mut *self.desc_ptr();
            desc.addr = self.buf_base as u64;
            desc.len = len as u32;
            desc.flags = VIRTQ_DESC_F_WRITE;
            desc.next = 0;

            let avail = &mut *self.avail_ptr();
            let idx = self.next_avail_idx;
            avail.ring[(idx % QUEUE_SIZE) as usize] = 0;
            core::sync::atomic::fence(Ordering::SeqCst);
            self.next_avail_idx = self.next_avail_idx.wrapping_add(1);
            avail.idx = self.next_avail_idx;
        }

        self.kick();
        Ok(())
    }

    pub(super) fn has_completed(&self) -> bool {
        // SAFETY: used_ptr() points into our exclusively-owned static VQ_REGION.
        unsafe {
            let used = &*self.used_ptr();
            used.idx != self.last_used_idx
        }
    }

    pub(super) fn get_received_bytes(&mut self, buf: &mut [u8]) -> usize {
        // SAFETY: used_ptr() points into our static VQ_REGION.
        // buf_base is our static DATA_BUF.
        let received_len = unsafe {
            let used = &*self.used_ptr();
            if used.idx == self.last_used_idx {
                return 0;
            }
            let used_elem = &used.ring[(self.last_used_idx % QUEUE_SIZE) as usize];
            self.last_used_idx = self.last_used_idx.wrapping_add(1);
            used_elem.len as usize
        };

        let copy_len = received_len.min(buf.len()).min(self.pending_len);
        // SAFETY: buf_base is a valid static buffer, copy_len <= BUFFER_SIZE and <= buf.len()
        unsafe {
            ptr::copy_nonoverlapping(self.buf_base as *const u8, buf.as_mut_ptr(), copy_len);
        }
        self.pending_len = 0;
        copy_len
    }

    fn kick(&self) {
        core::sync::atomic::fence(Ordering::SeqCst);
        if self.notify_port != 0 {
            // SAFETY: notify_port was set from a validated PCI BAR I/O port.
            // The out instruction notifies the device that new buffers are available.
            unsafe {
                core::arch::asm!("out dx, ax", in("dx") self.notify_port, in("ax") 0u16, options(nostack, preserves_flags));
            }
        } else if self.notify_mmio != 0 {
            // SAFETY: notify_mmio was set from a validated PCI BAR MMIO address.
            // Writing 0 to the notify register signals the device.
            unsafe {
                ptr::write_volatile(self.notify_mmio as *mut u16, 0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    // ── Struct sizes (VirtIO spec §2.6) ──────────────────────────────────

    #[test]
    fn test_virtq_desc_size_is_16_bytes() {
        assert_eq!(mem::size_of::<VirtqDesc>(), 16);
    }

    #[test]
    fn test_virtq_used_elem_size_is_8_bytes() {
        assert_eq!(mem::size_of::<VirtqUsedElem>(), 8);
    }

    // ── Layout constants (VirtIO §2.6.2 legacy layout) ───────────────────

    #[test]
    fn test_desc_offset_is_zero() {
        assert_eq!(DESC_OFFSET, 0);
    }

    #[test]
    fn test_avail_ring_offset_after_desc_table() {
        // 16 descriptors × 16 bytes = 256
        let desc_table_end = QUEUE_SIZE as usize * mem::size_of::<VirtqDesc>();
        assert_eq!(desc_table_end, 256);
        assert_eq!(AVAIL_OFFSET, desc_table_end);
    }

    #[test]
    fn test_used_ring_is_page_aligned() {
        assert_eq!(USED_OFFSET, 4096);
        assert_eq!(USED_OFFSET % 4096, 0);
    }

    #[test]
    fn test_vq_region_holds_all_rings() {
        // avail ring: flags(2) + idx(2) + ring(2×16) + used_event(2) = 38
        let avail_end = AVAIL_OFFSET + 4 + 2 * QUEUE_SIZE as usize + 2;
        assert!(avail_end <= USED_OFFSET, "avail ring overlaps used ring");

        // used ring: flags(2) + idx(2) + ring(8×16) + avail_event(2) = 134
        let used_end = USED_OFFSET + 4 + 8 * QUEUE_SIZE as usize + 2;
        assert!(used_end <= VQ_REGION_SIZE, "used ring overflows VQ region");
    }

    #[test]
    fn test_vq_region_is_two_pages() {
        assert_eq!(VQ_REGION_SIZE, 8192);
        assert_eq!(VQ_REGION_SIZE, 2 * 4096);
    }

    // ── Buffer constants ─────────────────────────────────────────────────

    #[test]
    fn test_buffer_size_is_one_page() {
        assert_eq!(BUFFER_SIZE, 4096);
    }

    #[test]
    fn test_queue_size_is_16() {
        assert_eq!(QUEUE_SIZE, 16);
    }

    #[test]
    fn test_write_flag_is_bit_1() {
        assert_eq!(VIRTQ_DESC_F_WRITE, 2);
        assert!(VIRTQ_DESC_F_WRITE.is_power_of_two());
    }

    // ── Static buffer alignment ──────────────────────────────────────────

    #[test]
    fn test_vq_region_buf_page_aligned() {
        assert_eq!(mem::align_of::<VirtqueueRegionBuf>(), 4096);
        assert_eq!(mem::size_of::<VirtqueueRegionBuf>(), VQ_REGION_SIZE);
    }

    #[test]
    fn test_data_buf_page_aligned() {
        assert_eq!(mem::align_of::<DataBuf>(), 4096);
        assert_eq!(mem::size_of::<DataBuf>(), BUFFER_SIZE);
    }

    // ── Default / zero initialization ────────────────────────────────────

    #[test]
    fn test_virtq_desc_default_zeroed() {
        let desc = VirtqDesc::default();
        assert_eq!(desc.addr, 0);
        assert_eq!(desc.len, 0);
        assert_eq!(desc.flags, 0);
        assert_eq!(desc.next, 0);
    }

    #[test]
    fn test_virtq_used_elem_default_zeroed() {
        let elem = VirtqUsedElem::default();
        assert_eq!(elem._id, 0);
        assert_eq!(elem.len, 0);
    }

    // ── RngQueue construction ────────────────────────────────────────────

    #[test]
    fn test_rng_queue_new_succeeds() {
        let q = RngQueue::new();
        assert!(q.is_ok(), "RngQueue::new() should succeed");
    }

    #[test]
    fn test_rng_queue_initial_state() {
        let q = RngQueue::new().unwrap();
        assert_eq!(q.last_used_idx, 0);
        assert_eq!(q.next_avail_idx, 0);
        assert_eq!(q.pending_len, 0);
        assert_eq!(q.notify_port, 0);
        assert_eq!(q.notify_mmio, 0);
    }

    #[test]
    fn test_rng_queue_base_page_aligned() {
        let q = RngQueue::new().unwrap();
        assert_eq!(q.vq_base & 0xFFF, 0, "VQ base must be page-aligned");
        assert_eq!(q.buf_base & 0xFFF, 0, "data buffer must be page-aligned");
    }

    #[test]
    fn test_rng_queue_desc_table_phys() {
        let q = RngQueue::new().unwrap();
        assert_eq!(q.desc_table_phys(), q.vq_base as u64);
    }

    #[test]
    fn test_rng_queue_set_notify_addr() {
        let mut q = RngQueue::new().unwrap();
        q.set_notify_addr(0x60B0);
        assert_eq!(q.notify_port, 0x60B0);
    }

    #[test]
    fn test_rng_queue_set_notify_mmio() {
        let mut q = RngQueue::new().unwrap();
        q.set_notify_mmio(0xFEBF_1010);
        assert_eq!(q.notify_mmio, 0xFEBF_1010);
    }

    #[test]
    fn test_has_completed_initially_false() {
        let q = RngQueue::new().unwrap();
        assert!(!q.has_completed());
    }

    #[test]
    fn test_get_received_bytes_returns_zero_when_not_completed() {
        let mut q = RngQueue::new().unwrap();
        let mut buf = [0u8; 64];
        let n = q.get_received_bytes(&mut buf);
        assert_eq!(n, 0);
    }
}
