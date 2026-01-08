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
use x86_64::PhysAddr;
use crate::memory::dma::{alloc_dma_coherent, DmaConstraints};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PixelFormat {
    X8R8G8B8,
    A8R8G8B8,
    R8G8B8,
    R5G6B5,
}

impl PixelFormat {
    pub fn bytes_per_pixel(&self) -> u8 {
        match self {
            PixelFormat::X8R8G8B8 | PixelFormat::A8R8G8B8 => 4,
            PixelFormat::R8G8B8 => 3,
            PixelFormat::R5G6B5 => 2,
        }
    }

    pub fn bits_per_pixel(&self) -> u8 {
        self.bytes_per_pixel() * 8
    }
}

#[derive(Clone, Copy, Debug)]
pub struct DisplayMode {
    pub width: u16,
    pub height: u16,
    pub bpp: u16,
    pub pitch: u32,
}

impl DisplayMode {
    pub fn new(width: u16, height: u16, bpp: u16) -> Self {
        let pitch = width as u32 * (bpp as u32 / 8);
        Self { width, height, bpp, pitch }
    }

    pub fn framebuffer_size(&self) -> usize {
        self.pitch as usize * self.height as usize
    }

    pub fn total_pixels(&self) -> usize {
        self.width as usize * self.height as usize
    }
}

#[derive(Clone, Debug)]
pub struct Framebuffer {
    pub fb_phys: PhysAddr,
    pub fb_len: usize,
    pub fb_virt: usize,
}

impl Framebuffer {
    pub fn new(phys: PhysAddr, len: usize, virt: usize) -> Self {
        Self {
            fb_phys: phys,
            fb_len: len,
            fb_virt: virt,
        }
    }

    pub fn as_mut_ptr(&self) -> *mut u8 {
        self.fb_virt as *mut u8
    }

    pub fn as_mut_ptr_u32(&self) -> *mut u32 {
        self.fb_virt as *mut u32
    }
}

#[derive(Clone, Debug)]
pub struct Backbuffer {
    va: usize,
    len: usize,
}

impl Backbuffer {
    pub fn new(bytes: usize) -> Result<Self, &'static str> {
        let constraints = DmaConstraints {
            alignment: 64,
            max_segment_size: bytes,
            dma32_only: false,
            coherent: true,
        };
        let dma_region = alloc_dma_coherent(bytes, constraints)
            .map_err(|_| "Failed to allocate DMA buffer")?;
        let va = dma_region.virt_addr.as_u64() as usize;
        // SAFETY: va is valid and properly aligned from DMA allocation
        unsafe { ptr::write_bytes(va as *mut u8, 0, bytes) };

        Ok(Backbuffer { va, len: bytes })
    }

    #[inline]
    pub fn as_mut_ptr(&self) -> *mut u8 {
        self.va as *mut u8
    }

    #[inline]
    pub fn as_mut_ptr_u32(&self) -> *mut u32 {
        self.va as *mut u32
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

#[derive(Clone)]
pub struct GpuSurface {
    pub mode: DisplayMode,
    pub format: PixelFormat,
    pub fb: Framebuffer,
    pub backbuf: Backbuffer,
}

impl GpuSurface {
    pub fn clear(&self, color: u32) {
        let pixels = (self.mode.pitch as usize / 4) * self.mode.height as usize;
        let mut p = self.backbuf.as_mut_ptr_u32();
        for _ in 0..pixels {
            // SAFETY: p is within allocated backbuffer bounds
            unsafe { ptr::write_volatile(p, color) };
            p = unsafe { p.add(1) };
        }
    }

    pub fn put_pixel(&self, x: u16, y: u16, color: u32) {
        if x >= self.mode.width || y >= self.mode.height {
            return;
        }

        let stride_px = (self.mode.pitch / 4) as usize;
        let offset = y as usize * stride_px + x as usize;
        let ptr = self.backbuf.as_mut_ptr_u32();

        // SAFETY: bounds checked above, offset is within backbuffer
        unsafe { ptr::write_volatile(ptr.add(offset), color) };
    }

    pub fn fill_rect(&self, x: u16, y: u16, w: u16, h: u16, color: u32) {
        if w == 0 || h == 0 {
            return;
        }

        let x2 = x.saturating_add(w).min(self.mode.width);
        let y2 = y.saturating_add(h).min(self.mode.height);
        if x >= self.mode.width || y >= self.mode.height {
            return;
        }

        let stride_px = (self.mode.pitch / 4) as usize;
        let mut row_ptr = self.backbuf.as_mut_ptr_u32()
            .wrapping_add(y as usize * stride_px + x as usize);

        for _row in y..y2 {
            let mut p = row_ptr;
            for _col in x..x2 {
                // SAFETY: bounds checked, pointer is within backbuffer
                unsafe { ptr::write_volatile(p, color) };
                p = unsafe { p.add(1) };
            }
            row_ptr = unsafe { row_ptr.add(stride_px) };
        }
    }

    pub fn blit(&self, x: u16, y: u16, src: &[u32], src_w: u16, src_h: u16) {
        if src_w == 0 || src_h == 0 {
            return;
        }

        let x2 = x.saturating_add(src_w).min(self.mode.width);
        let y2 = y.saturating_add(src_h).min(self.mode.height);
        if x >= self.mode.width || y >= self.mode.height {
            return;
        }

        let copy_w = (x2 - x) as usize;
        let stride_px = (self.mode.pitch / 4) as usize;
        for row in 0..(y2 - y) as usize {
            let dst_row = (y as usize + row) * stride_px + x as usize;
            let src_row = row * src_w as usize;
            let dst_ptr = self.backbuf.as_mut_ptr_u32().wrapping_add(dst_row);
            let src_ptr = src.as_ptr().wrapping_add(src_row);
            // SAFETY: bounds checked, both pointers valid within their buffers
            unsafe {
                for i in 0..copy_w {
                    let px = ptr::read_volatile(src_ptr.add(i));
                    ptr::write_volatile(dst_ptr.add(i), px);
                }
            }
        }
    }

    pub fn present(&self, rect: Option<(u16, u16, u16, u16)>) {
        let (x, y, w, h) = rect.unwrap_or((0, 0, self.mode.width, self.mode.height));
        if w == 0 || h == 0 {
            return;
        }

        let x2 = x.saturating_add(w).min(self.mode.width);
        let y2 = y.saturating_add(h).min(self.mode.height);
        if x >= self.mode.width || y >= self.mode.height {
            return;
        }

        let bytes_per_px = (self.mode.bpp / 8) as usize;
        let stride_bytes = self.mode.pitch as usize;
        let max_needed = y2 as usize * stride_bytes;
        if max_needed > self.fb.fb_len {
            return;
        }

        for row in y as usize..y2 as usize {
            let line_bytes = (x2 as usize - x as usize) * bytes_per_px;
            let dst = (self.fb.fb_virt + row * stride_bytes + x as usize * bytes_per_px) as *mut u8;
            let src = (self.backbuf.va + row * stride_bytes + x as usize * bytes_per_px) as *const u8;
            // SAFETY: bounds validated, both pointers within their respective buffers
            unsafe {
                for i in 0..line_bytes {
                    let b = ptr::read_volatile(src.add(i));
                    ptr::write_volatile(dst.add(i), b);
                }
            }
        }
    }

    pub fn width(&self) -> u16 {
        self.mode.width
    }

    pub fn height(&self) -> u16 {
        self.mode.height
    }

    pub fn pitch(&self) -> u32 {
        self.mode.pitch
    }
}
