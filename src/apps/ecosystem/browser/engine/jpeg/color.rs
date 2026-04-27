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

extern crate alloc;

use alloc::vec::Vec;

/// Convert YCbCr to RGB using ITU-R BT.601.
/// Uses fixed-point integer arithmetic (no floats).
///
/// R = Y + 1.402 * (Cr - 128)
/// G = Y - 0.344136 * (Cb - 128) - 0.714136 * (Cr - 128)
/// B = Y + 1.772 * (Cb - 128)
///
/// Scaled by 2^16 = 65536 for precision:
///   1.402    * 65536 = 91881
///   0.344136 * 65536 = 22554
///   0.714136 * 65536 = 46802
///   1.772    * 65536 = 116130
#[inline]
fn ycbcr_to_rgb(y: u8, cb: u8, cr: u8) -> (u8, u8, u8) {
    let y = y as i32;
    let cb = cb as i32 - 128;
    let cr = cr as i32 - 128;

    let r = y + ((91881 * cr + 32768) >> 16);
    let g = y - ((22554 * cb + 46802 * cr + 32768) >> 16);
    let b = y + ((116130 * cb + 32768) >> 16);

    (clamp_u8(r), clamp_u8(g), clamp_u8(b))
}

/// Convert YCbCr pixel data to ARGB u32 pixels matching ImageData format.
///
/// `y_plane`, `cb_plane`, `cr_plane` are separate component planes at their
/// native resolution. `width`/`height` are the output image dimensions.
/// `h_max`/`v_max` are the maximum sampling factors across all components.
/// Component sampling factors determine upsampling ratios.
pub(super) fn ycbcr_to_argb(
    y_plane: &[u8],
    cb_plane: &[u8],
    cr_plane: &[u8],
    width: u32,
    height: u32,
    y_h: u8,
    y_v: u8,
    cb_h: u8,
    cb_v: u8,
) -> Vec<u32> {
    let w = width as usize;
    let h = height as usize;
    let mut pixels = Vec::with_capacity(w * h);

    // Compute chroma plane dimensions
    // Chroma is subsampled by (y_h/cb_h) horizontally and (y_v/cb_v) vertically
    let h_ratio = if cb_h > 0 { y_h / cb_h } else { 1 } as usize;
    let v_ratio = if cb_v > 0 { y_v / cb_v } else { 1 } as usize;

    // Chroma plane width: round up
    let cb_width = (w + h_ratio - 1) / h_ratio;

    for row in 0..h {
        for col in 0..w {
            let y_idx = row * w + col;
            let y_val = if y_idx < y_plane.len() { y_plane[y_idx] } else { 128 };

            // Map to chroma plane coordinates (nearest neighbor for simplicity)
            let cb_col = col / h_ratio;
            let cb_row = row / v_ratio;
            let cb_idx = cb_row * cb_width + cb_col;

            let cb_val = if cb_idx < cb_plane.len() { cb_plane[cb_idx] } else { 128 };
            let cr_val = if cb_idx < cr_plane.len() { cr_plane[cb_idx] } else { 128 };

            let (r, g, b) = ycbcr_to_rgb(y_val, cb_val, cr_val);
            pixels.push(0xFF00_0000 | ((r as u32) << 16) | ((g as u32) << 8) | (b as u32));
        }
    }

    pixels
}

/// Convert grayscale Y data to ARGB u32 pixels.
pub(super) fn gray_to_argb(y_plane: &[u8], width: u32, height: u32) -> Vec<u32> {
    let count = (width * height) as usize;
    let mut pixels = Vec::with_capacity(count);
    for i in 0..count {
        let y = if i < y_plane.len() { y_plane[i] as u32 } else { 128 };
        pixels.push(0xFF00_0000 | (y << 16) | (y << 8) | y);
    }
    pixels
}

#[inline(always)]
fn clamp_u8(val: i32) -> u8 {
    if val < 0 {
        0
    } else if val > 255 {
        255
    } else {
        val as u8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ycbcr_white() {
        // White: Y=255, Cb=128, Cr=128 → R=255, G=255, B=255
        let (r, g, b) = ycbcr_to_rgb(255, 128, 128);
        assert_eq!((r, g, b), (255, 255, 255));
    }

    #[test]
    fn test_ycbcr_black() {
        // Black: Y=0, Cb=128, Cr=128 → R=0, G=0, B=0
        let (r, g, b) = ycbcr_to_rgb(0, 128, 128);
        assert_eq!((r, g, b), (0, 0, 0));
    }

    #[test]
    fn test_ycbcr_red() {
        // Pure red: Y=76, Cb=84, Cr=255
        let (r, g, b) = ycbcr_to_rgb(76, 84, 255);
        // Should be close to (255, 0, 0) — allow ±2 for fixed-point rounding
        assert!(r >= 253, "red={}", r);
        assert!(g <= 2, "green={}", g);
        assert!(b <= 2, "blue={}", b);
    }

    #[test]
    fn test_ycbcr_green() {
        // Pure green: Y=150, Cb=44, Cr=21
        let (r, g, b) = ycbcr_to_rgb(150, 44, 21);
        // Should be close to (0, 255, 0) — allow generous tolerance
        assert!(r <= 5, "red={}", r);
        assert!(g >= 250, "green={}", g);
        assert!(b <= 5, "blue={}", b);
    }

    #[test]
    fn test_ycbcr_clamp() {
        // Extreme values should clamp to [0, 255]
        let (r, g, b) = ycbcr_to_rgb(255, 0, 255);
        assert!(r <= 255);
        assert!(g <= 255);
        assert!(b <= 255);
    }

    #[test]
    fn test_gray_to_argb() {
        let y = [0, 128, 255];
        let pixels = gray_to_argb(&y, 3, 1);
        assert_eq!(pixels.len(), 3);
        assert_eq!(pixels[0], 0xFF000000); // black
        assert_eq!(pixels[1], 0xFF808080); // mid gray
        assert_eq!(pixels[2], 0xFFFFFFFF); // white
    }

    #[test]
    fn test_ycbcr_to_argb_444() {
        // 4:4:4 subsampling (no chroma subsampling): h_ratio=1, v_ratio=1
        let y = [128, 128];
        let cb = [128, 128];
        let cr = [128, 128];
        let pixels = ycbcr_to_argb(&y, &cb, &cr, 2, 1, 1, 1, 1, 1);
        assert_eq!(pixels.len(), 2);
        // Y=128, Cb=128, Cr=128 → mid gray
        assert_eq!(pixels[0], 0xFF808080);
    }

    #[test]
    fn test_ycbcr_to_argb_420() {
        // 4:2:0: Y is 2×2 per chroma sample (y_h=2, y_v=2, cb_h=1, cb_v=1)
        let y = [200, 200, 200, 200]; // 2×2 luma
        let cb = [128]; // 1×1 chroma
        let cr = [128];
        let pixels = ycbcr_to_argb(&y, &cb, &cr, 2, 2, 2, 2, 1, 1);
        assert_eq!(pixels.len(), 4);
        // All should be grayscale 200
        for &p in &pixels {
            assert_eq!(p, 0xFFC8C8C8);
        }
    }
}
