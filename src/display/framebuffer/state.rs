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

use crate::display::error::DisplayError;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

pub(super) static FB_INIT: AtomicBool = AtomicBool::new(false);
pub(super) static FB_ADDR: AtomicU64 = AtomicU64::new(0);
pub(super) static FB_WIDTH: AtomicU32 = AtomicU32::new(0);
pub(super) static FB_HEIGHT: AtomicU32 = AtomicU32::new(0);
pub(super) static FB_STRIDE: AtomicU32 = AtomicU32::new(0);
pub(super) static FB_BPP: AtomicU32 = AtomicU32::new(0);

#[derive(Debug, Clone, Copy)]
pub struct FramebufferInfo {
    pub addr: u64,
    pub width: u32,
    pub height: u32,
    pub stride: u32,
    pub bpp: u32,
}

pub struct Framebuffer;

impl Framebuffer {
    pub fn info() -> Result<FramebufferInfo, DisplayError> {
        if !FB_INIT.load(Ordering::Acquire) {
            return Err(DisplayError::NotInitialized);
        }
        Ok(FramebufferInfo {
            addr: FB_ADDR.load(Ordering::Relaxed),
            width: FB_WIDTH.load(Ordering::Relaxed),
            height: FB_HEIGHT.load(Ordering::Relaxed),
            stride: FB_STRIDE.load(Ordering::Relaxed),
            bpp: FB_BPP.load(Ordering::Relaxed),
        })
    }
}

pub fn register_framebuffer(info: FramebufferInfo) -> Result<(), DisplayError> {
    if info.addr == 0 {
        return Err(DisplayError::InvalidAddress);
    }
    if info.width == 0 || info.height == 0 {
        return Err(DisplayError::InvalidFormat);
    }
    FB_ADDR.store(info.addr, Ordering::Relaxed);
    FB_WIDTH.store(info.width, Ordering::Relaxed);
    FB_HEIGHT.store(info.height, Ordering::Relaxed);
    FB_STRIDE.store(info.stride, Ordering::Relaxed);
    FB_BPP.store(info.bpp, Ordering::Relaxed);
    FB_INIT.store(true, Ordering::Release);
    Ok(())
}

pub fn get_framebuffer() -> Result<FramebufferInfo, DisplayError> {
    Framebuffer::info()
}
