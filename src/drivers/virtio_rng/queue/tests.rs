// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::constants::*;
use super::core::RngQueue;
use super::types::*;
use core::mem;

#[test]
fn test_virtq_desc_size_is_16_bytes() {
    assert_eq!(mem::size_of::<VirtqDesc>(), 16);
}
#[test]
fn test_virtq_used_elem_size_is_8_bytes() {
    assert_eq!(mem::size_of::<VirtqUsedElem>(), 8);
}
#[test]
fn test_desc_offset_is_zero() {
    assert_eq!(DESC_OFFSET, 0);
}

#[test]
fn test_avail_ring_offset_after_desc_table() {
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
    let avail_end = AVAIL_OFFSET + 4 + 2 * QUEUE_SIZE as usize + 2;
    assert!(avail_end <= USED_OFFSET, "avail ring overlaps used ring");
    let used_end = USED_OFFSET + 4 + 8 * QUEUE_SIZE as usize + 2;
    assert!(used_end <= VQ_REGION_SIZE, "used ring overflows VQ region");
}

#[test]
fn test_vq_region_is_two_pages() {
    assert_eq!(VQ_REGION_SIZE, 8192);
    assert_eq!(VQ_REGION_SIZE, 2 * 4096);
}
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
