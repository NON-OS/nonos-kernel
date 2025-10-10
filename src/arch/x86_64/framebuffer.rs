//! Minimal UEFI GOP-backed framebuffer for 32bpp modes (RGB/BGR/Bitmask).
//! Safe, no_std, no allocator. Consume fields from ZeroStateBootInfo.

#![allow(dead_code)]

use core::ptr::{slice_from_raw_parts_mut, NonNull};

/// Mirror of bootloader pixel-format codes (keep in sync with nonos_boot::handoff::fb_format)
pub mod fb_format {
    pub const UNKNOWN: u16  = 0;
    pub const RGB: u16      = 1;
    pub const BGR: u16      = 2;
    pub const BITMASK: u16  = 3;
    pub const BLTONLY: u16  = 4; // not supported here
}

/// Tiny view into the linear framebuffer.
pub struct Framebuffer {
    /// Virtual pointer to first pixel (we assume HHDM/ident-map makes phys usable)
    base: NonNull<u8>,
    /// Total bytes available at `base`
    size: usize,
    /// Bytes per scanline
    pitch: u32,
    /// Width/height in pixels
    pub width: u32,
    pub height: u32,
    /// Bits per pixel (expect 32)
    bpp: u16,
    /// Pixel layout
    fmt: u16,
}

impl Framebuffer {
    /// Create from handoff fields. If anything looks invalid, returns None.
    ///
    /// # Safety
    /// Caller guarantees that `fb_base_virt` is a valid, writable mapping of the
    /// physical framebuffer with at least `fb_size` bytes.
    pub unsafe fn from_handoff(
        fb_base_virt: u64,
        fb_size: u64,
        fb_pitch: u32,
        fb_width: u32,
        fb_height: u32,
        fb_bpp: u16,
        fb_fmt: u16,
    ) -> Option<Self> {
        if fb_base_virt == 0 || fb_size == 0 || fb_width == 0 || fb_height == 0 {
            return None;
        }
        if fb_bpp != 32 {
            // Keep it simple for now
            return None;
        }
        let base_ptr = (fb_base_virt as *mut u8);
        let nn = NonNull::new(base_ptr)?;
        Some(Self {
            base: nn,
            size: fb_size as usize,
            pitch: fb_pitch,
            width: fb_width,
            height: fb_height,
            bpp: fb_bpp,
            fmt: fb_fmt,
        })
    }

    #[inline]
    fn row_slice_mut(&mut self, y: u32) -> Option<&mut [u8]> {
        let off = (y as usize).checked_mul(self.pitch as usize)?;
        if off >= self.size { return None; }
        let row_len = core::cmp::min(self.pitch as usize, self.size - off);
        let row_ptr = unsafe { self.base.as_ptr().add(off) };
        Some(unsafe { &mut *slice_from_raw_parts_mut(row_ptr, row_len) })
    }

    /// Clear full screen to an RGB color (8-bit channels). Accepts logical RGB; we’ll
    /// reorder for BGR when needed.
    pub fn clear(&mut self, r: u8, g: u8, b: u8) {
        for y in 0..self.height {
            if let Some(row) = self.row_slice_mut(y) {
                for x in 0..self.width {
                    let px = (x as usize) * 4;
                    if px + 3 >= row.len() { break; }
                    match self.fmt {
                        fb_format::RGB | fb_format::BITMASK => {
                            row[px + 0] = b; // little-endian BGRA in memory for RGB layout
                            row[px + 1] = g;
                            row[px + 2] = r;
                            row[px + 3] = 0xFF;
                        }
                        fb_format::BGR => {
                            row[px + 0] = r; // reversed
                            row[px + 1] = g;
                            row[px + 2] = b;
                            row[px + 3] = 0xFF;
                        }
                        _ => { /* BLTONLY/UNKNOWN: ignore */ }
                    }
                }
            }
        }
    }

    /// Put a single pixel if within bounds.
    pub fn put_pixel(&mut self, x: u32, y: u32, r: u8, g: u8, b: u8) {
        if x >= self.width || y >= self.height { return; }
        if let Some(row) = self.row_slice_mut(y) {
            let px = (x as usize) * 4;
            if px + 3 >= row.len() { return; }
            match self.fmt {
                fb_format::RGB | fb_format::BITMASK => {
                    row[px + 0] = b;
                    row[px + 1] = g;
                    row[px + 2] = r;
                    row[px + 3] = 0xFF;
                }
                fb_format::BGR => {
                    row[px + 0] = r;
                    row[px + 1] = g;
                    row[px + 2] = b;
                    row[px + 3] = 0xFF;
                }
                _ => {}
            }
        }
    }

    /// Draw a filled rectangle (clamped).
    pub fn fill_rect(&mut self, x: u32, y: u32, w: u32, h: u32, r: u8, g: u8, b: u8) {
        let x2 = core::cmp::min(self.width, x.saturating_add(w));
        let y2 = core::cmp::min(self.height, y.saturating_add(h));
        for yy in y..y2 {
            for xx in x..x2 {
                self.put_pixel(xx, yy, r, g, b);
            }
        }
    }

    /// Quick test pattern: border + gradient bar.
    pub fn test_pattern(&mut self) {
        // dark clear
        self.clear(8, 8, 12);
        // border
        let bw = 2;
        self.fill_rect(0, 0, self.width, bw, 220, 220, 220);
        self.fill_rect(0, self.height - bw, self.width, bw, 220, 220, 220);
        self.fill_rect(0, 0, bw, self.height, 220, 220, 220);
        self.fill_rect(self.width - bw, 0, bw, self.height, 220, 220, 220);

        // gradient bar
        let gh = core::cmp::min(64, self.height.saturating_sub(2*bw));
        for x in (bw)..(self.width - bw) {
            let t = ((x - bw) * 255 / (self.width - 2*bw)).min(255) as u8;
            self.fill_rect(x, self.height/2 - gh/2, 1, gh, t, 128, 255 - t);
        }
    }
}

/// Helper to convert a physical address to a usable virtual address.
/// If your kernel has an HHDM of 0xFFFF_8000_0000_0000, keep this.
#[inline]
pub fn phys_to_virt(phys: u64) -> u64 {
    const HHDM: u64 = 0xFFFF_8000_0000_0000;
    HHDM.wrapping_add(phys)
}

/// Bootstrap the framebuffer from a `ZeroStateBootInfo` (shared layout with bootloader).
/// Returns `None` if not available / unsupported.
pub fn init_from_handoff(h: &crate::handoff::ZeroStateBootInfo) -> Option<Framebuffer> {
    // Expect these accessors/fields to exist in your kernel handoff module.
    let base_phys = h.fb_base();
    let size      = h.fb_size();
    let pitch     = h.fb_pitch();
    let width     = h.fb_width();
    let height    = h.fb_height();
    let bpp       = h.fb_bpp();
    let fmt       = h.fb_format();

    if base_phys == 0 || size == 0 { return None; }

    // Map phys → virt using HHDM (or identity if you run that way)
    let base_virt = phys_to_virt(base_phys);

    unsafe { Framebuffer::from_handoff(base_virt, size, pitch, width, height, bpp, fmt) }
}
// Example usage in your kernel main.rs: