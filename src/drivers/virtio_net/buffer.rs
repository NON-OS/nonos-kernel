// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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
use x86_64::{PhysAddr, VirtAddr};

use crate::memory::dma::{alloc_dma_coherent, DmaConstraints};
use super::constants::DMA_ALIGNMENT;
use super::error::VirtioNetError;

pub struct PacketBuffer {
    dma_virt: VirtAddr,
    dma_phys: PhysAddr,
    len: usize,
    cap: usize,
    in_use: bool,
}

impl PacketBuffer {
    pub fn new(size: usize) -> Result<Self, &'static str> {
        if size == 0 {
            return Err("buffer: cannot create zero-sized buffer");
        }

        let constraints = DmaConstraints {
            alignment: DMA_ALIGNMENT,
            max_segment_size: size,
            dma32_only: false,
            coherent: true,
        };

        let dma_region = alloc_dma_coherent(size, constraints)
            .map_err(|_| "Failed to allocate DMA buffer")?;
        let (va, pa) = (dma_region.virt_addr, dma_region.phys_addr);

        // SAFETY: va is valid DMA memory we just allocated
        unsafe {
            ptr::write_bytes(va.as_mut_ptr::<u8>(), 0, size);
        }

        Ok(Self {
            dma_virt: va,
            dma_phys: pa,
            len: 0,
            cap: size,
            in_use: false,
        })
    }

    pub fn default_size() -> Result<Self, &'static str> {
        Self::new(2048)
    }

    pub fn write(&mut self, data: &[u8]) -> Result<(), VirtioNetError> {
        if data.len() > self.cap {
            return Err(VirtioNetError::BufferTooSmall);
        }

        // SAFETY: dma_virt is valid DMA memory, data.len() <= cap
        unsafe {
            ptr::copy_nonoverlapping(
                data.as_ptr(),
                self.dma_virt.as_mut_ptr::<u8>(),
                data.len(),
            );
        }
        self.len = data.len();
        Ok(())
    }

    pub fn write_at(&mut self, offset: usize, data: &[u8]) -> Result<(), VirtioNetError> {
        let end = offset.checked_add(data.len()).ok_or(VirtioNetError::BufferTooSmall)?;

        if end > self.cap {
            return Err(VirtioNetError::BufferTooSmall);
        }

        // SAFETY: dma_virt is valid DMA memory, end <= cap
        unsafe {
            let dst = self.dma_virt.as_mut_ptr::<u8>().add(offset);
            ptr::copy_nonoverlapping(data.as_ptr(), dst, data.len());
        }

        if end > self.len {
            self.len = end;
        }

        Ok(())
    }

    pub fn read(&self, offset: usize, len: usize) -> Result<&[u8], VirtioNetError> {
        let end = offset.checked_add(len).ok_or(VirtioNetError::BufferTooSmall)?;

        if end > self.len {
            return Err(VirtioNetError::BufferTooSmall);
        }

        // SAFETY: dma_virt is valid DMA memory, end <= len
        unsafe {
            let ptr = self.dma_virt.as_ptr::<u8>().add(offset);
            Ok(core::slice::from_raw_parts(ptr, len))
        }
    }

    pub fn read_all(&self) -> &[u8] {
        // SAFETY: dma_virt is valid DMA memory
        unsafe {
            core::slice::from_raw_parts(self.dma_virt.as_ptr::<u8>(), self.len)
        }
    }

    pub fn copy_to(&self, offset: usize, dest: &mut [u8]) -> Result<usize, VirtioNetError> {
        if offset >= self.len {
            return Ok(0);
        }

        let available = self.len - offset;
        let to_copy = core::cmp::min(available, dest.len());

        // SAFETY: dma_virt is valid DMA memory, offset < len
        unsafe {
            let src = self.dma_virt.as_ptr::<u8>().add(offset);
            ptr::copy_nonoverlapping(src, dest.as_mut_ptr(), to_copy);
        }

        Ok(to_copy)
    }

    pub fn zero(&mut self) {
        // SAFETY: dma_virt is valid DMA memory
        unsafe {
            ptr::write_bytes(self.dma_virt.as_mut_ptr::<u8>(), 0, self.cap);
        }
        self.len = 0;
    }

    pub fn clear(&mut self) {
        self.zero();
    }

    #[inline]
    pub fn phys(&self) -> PhysAddr {
        self.dma_phys
    }

    #[inline]
    pub fn virt(&self) -> VirtAddr {
        self.dma_virt
    }

    #[inline]
    pub fn capacity(&self) -> usize {
        self.cap
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[inline]
    pub fn set_len(&mut self, n: usize) {
        self.len = core::cmp::min(n, self.cap);
    }

    pub fn acquire(&mut self) -> Result<(), VirtioNetError> {
        if self.in_use {
            return Err(VirtioNetError::GenericError);
        }
        self.in_use = true;
        Ok(())
    }

    pub fn release(&mut self) {
        self.in_use = false;
        self.zero();
    }

    #[inline]
    pub fn is_in_use(&self) -> bool {
        self.in_use
    }

    #[inline]
    pub fn remaining(&self) -> usize {
        self.cap - self.len
    }

    #[inline]
    pub unsafe fn as_mut_ptr(&self) -> *mut u8 {
        self.dma_virt.as_mut_ptr::<u8>()
    }

    #[inline]
    pub fn as_ptr(&self) -> *const u8 {
        self.dma_virt.as_ptr::<u8>()
    }
}

impl Drop for PacketBuffer {
    fn drop(&mut self) {
        self.zero();
    }
}

pub struct BufferPool {
    buffers: alloc::vec::Vec<PacketBuffer>,
    free_indices: alloc::collections::VecDeque<usize>,
    buffer_size: usize,
}

impl BufferPool {
    pub fn new(count: usize, buffer_size: usize) -> Result<Self, &'static str> {
        let mut buffers = alloc::vec::Vec::with_capacity(count);
        let mut free_indices = alloc::collections::VecDeque::with_capacity(count);
        for i in 0..count {
            buffers.push(PacketBuffer::new(buffer_size)?);
            free_indices.push_back(i);
        }

        Ok(Self {
            buffers,
            free_indices,
            buffer_size,
        })
    }

    pub fn acquire(&mut self) -> Option<(usize, &mut PacketBuffer)> {
        let idx = self.free_indices.pop_front()?;
        let buf = &mut self.buffers[idx];
        if buf.acquire().is_err() {
            self.free_indices.push_back(idx);
            return None;
        }

        Some((idx, buf))
    }

    pub fn release(&mut self, idx: usize) {
        if idx < self.buffers.len() {
            self.buffers[idx].release();
            self.free_indices.push_back(idx);
        }
    }

    pub fn get(&self, idx: usize) -> Option<&PacketBuffer> {
        self.buffers.get(idx)
    }

    pub fn get_mut(&mut self, idx: usize) -> Option<&mut PacketBuffer> {
        self.buffers.get_mut(idx)
    }

    pub fn available(&self) -> usize {
        self.free_indices.len()
    }

    pub fn total(&self) -> usize {
        self.buffers.len()
    }

    pub fn buffer_size(&self) -> usize {
        self.buffer_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer_bounds() {
    }

    #[test]
    fn test_buffer_ownership() {
    }
}
