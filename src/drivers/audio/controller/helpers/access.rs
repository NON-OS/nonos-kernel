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

use x86_64::VirtAddr;

use crate::memory::mmio::{mmio_r8, mmio_r16, mmio_r32, mmio_w8, mmio_w16, mmio_w32};

use super::super::super::constants::*;

pub trait RegisterAccess {
    fn base_addr(&self) -> usize;

    #[inline]
    fn read_reg32(&self, offset: usize) -> u32 {
        debug_assert!(offset % 4 == 0, "32-bit register offset must be 4-byte aligned");
        mmio_r32(VirtAddr::new((self.base_addr() + offset) as u64))
    }

    #[inline]
    fn write_reg32(&self, offset: usize, value: u32) {
        debug_assert!(offset % 4 == 0, "32-bit register offset must be 4-byte aligned");
        mmio_w32(VirtAddr::new((self.base_addr() + offset) as u64), value)
    }

    #[inline]
    fn read_reg16(&self, offset: usize) -> u16 {
        debug_assert!(offset % 2 == 0, "16-bit register offset must be 2-byte aligned");
        mmio_r16(VirtAddr::new((self.base_addr() + offset) as u64))
    }

    #[inline]
    fn write_reg16(&self, offset: usize, value: u16) {
        debug_assert!(offset % 2 == 0, "16-bit register offset must be 2-byte aligned");
        mmio_w16(VirtAddr::new((self.base_addr() + offset) as u64), value)
    }

    #[inline]
    fn read_reg8(&self, offset: usize) -> u8 {
        mmio_r8(VirtAddr::new((self.base_addr() + offset) as u64))
    }

    #[inline]
    fn write_reg8(&self, offset: usize, value: u8) {
        mmio_w8(VirtAddr::new((self.base_addr() + offset) as u64), value)
    }

    #[inline]
    fn modify_reg32(&self, offset: usize, clear_mask: u32, set_bits: u32) -> u32 {
        let current = self.read_reg32(offset);
        let new_value = (current & !clear_mask) | set_bits;
        self.write_reg32(offset, new_value);
        new_value
    }

    #[inline]
    fn set_reg32_bits(&self, offset: usize, bits: u32) {
        let current = self.read_reg32(offset);
        self.write_reg32(offset, current | bits);
    }

    #[inline]
    fn clear_reg32_bits(&self, offset: usize, bits: u32) {
        let current = self.read_reg32(offset);
        self.write_reg32(offset, current & !bits);
    }

    #[inline]
    fn stream_regs(&self, stream_index: u8) -> usize {
        debug_assert!(stream_index >= 1, "Stream index must be 1-based");
        debug_assert!((stream_index as usize) <= MAX_STREAMS, "Stream index out of range");
        self.base_addr() + STREAM_BASE + (stream_index as usize - 1) * STREAM_STRIDE
    }

    #[inline]
    fn read_stream_reg32(&self, stream_index: u8, offset: usize) -> u32 {
        debug_assert!(offset < STREAM_STRIDE, "Stream register offset out of range");
        let addr = self.stream_regs(stream_index) + offset;
        mmio_r32(VirtAddr::new(addr as u64))
    }

    #[inline]
    fn write_stream_reg32(&self, stream_index: u8, offset: usize, value: u32) {
        debug_assert!(offset < STREAM_STRIDE, "Stream register offset out of range");
        let addr = self.stream_regs(stream_index) + offset;
        mmio_w32(VirtAddr::new(addr as u64), value)
    }

    #[inline]
    fn read_stream_reg16(&self, stream_index: u8, offset: usize) -> u16 {
        debug_assert!(offset < STREAM_STRIDE, "Stream register offset out of range");
        let addr = self.stream_regs(stream_index) + offset;
        mmio_r16(VirtAddr::new(addr as u64))
    }

    #[inline]
    fn write_stream_reg16(&self, stream_index: u8, offset: usize, value: u16) {
        debug_assert!(offset < STREAM_STRIDE, "Stream register offset out of range");
        let addr = self.stream_regs(stream_index) + offset;
        mmio_w16(VirtAddr::new(addr as u64), value)
    }

    #[inline]
    fn read_stream_reg8(&self, stream_index: u8, offset: usize) -> u8 {
        debug_assert!(offset < STREAM_STRIDE, "Stream register offset out of range");
        let addr = self.stream_regs(stream_index) + offset;
        mmio_r8(VirtAddr::new(addr as u64))
    }

    #[inline]
    fn write_stream_reg8(&self, stream_index: u8, offset: usize, value: u8) {
        debug_assert!(offset < STREAM_STRIDE, "Stream register offset out of range");
        let addr = self.stream_regs(stream_index) + offset;
        mmio_w8(VirtAddr::new(addr as u64), value)
    }

    #[inline]
    fn spin_until<F: Fn() -> bool>(&self, cond: F, max_spins: u32) -> bool {
        spin_until(cond, max_spins)
    }

    #[inline]
    fn spin_while<F: Fn() -> bool>(&self, cond: F, max_spins: u32) -> bool {
        spin_while(cond, max_spins)
    }
}

#[inline]
pub fn spin_until<F: Fn() -> bool>(cond: F, mut max_spins: u32) -> bool {
    while max_spins > 0 {
        if cond() {
            return true;
        }
        core::hint::spin_loop();
        max_spins -= 1;
    }
    false
}

#[inline]
pub fn spin_while<F: Fn() -> bool>(cond: F, mut max_spins: u32) -> bool {
    while max_spins > 0 {
        if !cond() {
            return true;
        }
        core::hint::spin_loop();
        max_spins -= 1;
    }
    false
}
