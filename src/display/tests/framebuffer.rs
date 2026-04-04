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

use crate::display::*;

#[test]
fn test_framebuffer_info_creation() {
    let info = FramebufferInfo {
        addr: 0xB8000,
        width: 1920,
        height: 1080,
        stride: 7680,
        bpp: 32,
    };
    assert_eq!(info.addr, 0xB8000);
    assert_eq!(info.width, 1920);
    assert_eq!(info.height, 1080);
    assert_eq!(info.stride, 7680);
    assert_eq!(info.bpp, 32);
}

#[test]
fn test_framebuffer_info_clone() {
    let info = FramebufferInfo {
        addr: 0xFD000000,
        width: 800,
        height: 600,
        stride: 3200,
        bpp: 32,
    };
    let cloned = info.clone();
    assert_eq!(info.addr, cloned.addr);
    assert_eq!(info.width, cloned.width);
    assert_eq!(info.height, cloned.height);
    assert_eq!(info.stride, cloned.stride);
    assert_eq!(info.bpp, cloned.bpp);
}

#[test]
fn test_framebuffer_info_copy() {
    let info = FramebufferInfo {
        addr: 0xE0000000,
        width: 1024,
        height: 768,
        stride: 4096,
        bpp: 32,
    };
    let copied = info;
    assert_eq!(info.addr, copied.addr);
    assert_eq!(info.width, copied.width);
}

#[test]
fn test_framebuffer_info_debug() {
    let info = FramebufferInfo {
        addr: 0x12345678,
        width: 640,
        height: 480,
        stride: 2560,
        bpp: 32,
    };
    let debug = alloc::format!("{:?}", info);
    assert!(debug.contains("FramebufferInfo"));
    assert!(debug.contains("addr"));
    assert!(debug.contains("width"));
    assert!(debug.contains("height"));
}

#[test]
fn test_framebuffer_info_standard_resolutions() {
    let hd = FramebufferInfo {
        addr: 0x10000000,
        width: 1920,
        height: 1080,
        stride: 1920 * 4,
        bpp: 32,
    };
    assert_eq!(hd.width * hd.height, 2073600);

    let fhd_plus = FramebufferInfo {
        addr: 0x10000000,
        width: 2560,
        height: 1440,
        stride: 2560 * 4,
        bpp: 32,
    };
    assert_eq!(fhd_plus.width * fhd_plus.height, 3686400);

    let uhd = FramebufferInfo {
        addr: 0x10000000,
        width: 3840,
        height: 2160,
        stride: 3840 * 4,
        bpp: 32,
    };
    assert_eq!(uhd.width * uhd.height, 8294400);
}

#[test]
fn test_framebuffer_info_stride_calculation() {
    let info = FramebufferInfo {
        addr: 0x10000000,
        width: 1920,
        height: 1080,
        stride: 1920 * 4,
        bpp: 32,
    };
    assert_eq!(info.stride, info.width * (info.bpp / 8));
}

#[test]
fn test_framebuffer_info_stride_with_padding() {
    let info = FramebufferInfo {
        addr: 0x10000000,
        width: 1920,
        height: 1080,
        stride: 8192,
        bpp: 32,
    };
    assert!(info.stride >= info.width * (info.bpp / 8));
}

#[test]
fn test_framebuffer_info_vga_resolution() {
    let vga = FramebufferInfo {
        addr: 0xA0000,
        width: 640,
        height: 480,
        stride: 640 * 4,
        bpp: 32,
    };
    assert_eq!(vga.width, 640);
    assert_eq!(vga.height, 480);
}

#[test]
fn test_framebuffer_info_svga_resolution() {
    let svga = FramebufferInfo {
        addr: 0xE0000000,
        width: 800,
        height: 600,
        stride: 800 * 4,
        bpp: 32,
    };
    assert_eq!(svga.width, 800);
    assert_eq!(svga.height, 600);
}

#[test]
fn test_framebuffer_info_xga_resolution() {
    let xga = FramebufferInfo {
        addr: 0xE0000000,
        width: 1024,
        height: 768,
        stride: 1024 * 4,
        bpp: 32,
    };
    assert_eq!(xga.width, 1024);
    assert_eq!(xga.height, 768);
}

#[test]
fn test_framebuffer_info_sxga_resolution() {
    let sxga = FramebufferInfo {
        addr: 0xE0000000,
        width: 1280,
        height: 1024,
        stride: 1280 * 4,
        bpp: 32,
    };
    assert_eq!(sxga.width, 1280);
    assert_eq!(sxga.height, 1024);
}

#[test]
fn test_framebuffer_info_bpp_24() {
    let info = FramebufferInfo {
        addr: 0xE0000000,
        width: 1920,
        height: 1080,
        stride: 1920 * 3,
        bpp: 24,
    };
    assert_eq!(info.bpp, 24);
    assert_eq!(info.stride, info.width * 3);
}

#[test]
fn test_framebuffer_info_bpp_16() {
    let info = FramebufferInfo {
        addr: 0xE0000000,
        width: 1920,
        height: 1080,
        stride: 1920 * 2,
        bpp: 16,
    };
    assert_eq!(info.bpp, 16);
    assert_eq!(info.stride, info.width * 2);
}

#[test]
fn test_framebuffer_info_bpp_8() {
    let info = FramebufferInfo {
        addr: 0xE0000000,
        width: 320,
        height: 200,
        stride: 320,
        bpp: 8,
    };
    assert_eq!(info.bpp, 8);
    assert_eq!(info.stride, info.width);
}

#[test]
fn test_framebuffer_info_large_address() {
    let info = FramebufferInfo {
        addr: 0xFFFF_FFFF_FFFF_0000,
        width: 1920,
        height: 1080,
        stride: 7680,
        bpp: 32,
    };
    assert_eq!(info.addr, 0xFFFF_FFFF_FFFF_0000);
}

#[test]
fn test_framebuffer_info_buffer_size() {
    let info = FramebufferInfo {
        addr: 0xE0000000,
        width: 1920,
        height: 1080,
        stride: 7680,
        bpp: 32,
    };
    let buffer_size = (info.stride as u64) * (info.height as u64);
    assert_eq!(buffer_size, 8294400);
}

#[test]
fn test_framebuffer_info_pixel_offset() {
    let info = FramebufferInfo {
        addr: 0xE0000000,
        width: 1920,
        height: 1080,
        stride: 7680,
        bpp: 32,
    };
    let x = 100u32;
    let y = 200u32;
    let offset = (y as u64) * (info.stride as u64) + (x as u64) * ((info.bpp / 8) as u64);
    assert_eq!(offset, 200 * 7680 + 100 * 4);
}

#[test]
fn test_framebuffer_info_row_offset() {
    let info = FramebufferInfo {
        addr: 0xE0000000,
        width: 1920,
        height: 1080,
        stride: 7680,
        bpp: 32,
    };
    let row_offset = info.stride as u64;
    assert_eq!(row_offset, 7680);
}

#[test]
fn test_register_framebuffer_invalid_address_zero() {
    let info = FramebufferInfo {
        addr: 0,
        width: 1920,
        height: 1080,
        stride: 7680,
        bpp: 32,
    };
    let result = register_framebuffer(info);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), DisplayError::InvalidAddress);
}

#[test]
fn test_register_framebuffer_invalid_width_zero() {
    let info = FramebufferInfo {
        addr: 0xE0000000,
        width: 0,
        height: 1080,
        stride: 7680,
        bpp: 32,
    };
    let result = register_framebuffer(info);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), DisplayError::InvalidFormat);
}

#[test]
fn test_register_framebuffer_invalid_height_zero() {
    let info = FramebufferInfo {
        addr: 0xE0000000,
        width: 1920,
        height: 0,
        stride: 7680,
        bpp: 32,
    };
    let result = register_framebuffer(info);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), DisplayError::InvalidFormat);
}

#[test]
fn test_register_framebuffer_invalid_both_dimensions_zero() {
    let info = FramebufferInfo {
        addr: 0xE0000000,
        width: 0,
        height: 0,
        stride: 0,
        bpp: 32,
    };
    let result = register_framebuffer(info);
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), DisplayError::InvalidFormat);
}

#[test]
fn test_framebuffer_info_widescreen_16_9() {
    let info = FramebufferInfo {
        addr: 0xE0000000,
        width: 1920,
        height: 1080,
        stride: 7680,
        bpp: 32,
    };
    let aspect_width = info.width / 120;
    let aspect_height = info.height / 120;
    assert_eq!(aspect_width, 16);
    assert_eq!(aspect_height, 9);
}

#[test]
fn test_framebuffer_info_widescreen_16_10() {
    let info = FramebufferInfo {
        addr: 0xE0000000,
        width: 1920,
        height: 1200,
        stride: 7680,
        bpp: 32,
    };
    let aspect_width = info.width / 120;
    let aspect_height = info.height / 120;
    assert_eq!(aspect_width, 16);
    assert_eq!(aspect_height, 10);
}

#[test]
fn test_framebuffer_info_standard_4_3() {
    let info = FramebufferInfo {
        addr: 0xE0000000,
        width: 1024,
        height: 768,
        stride: 4096,
        bpp: 32,
    };
    let aspect_width = info.width / 256;
    let aspect_height = info.height / 256;
    assert_eq!(aspect_width, 4);
    assert_eq!(aspect_height, 3);
}

#[test]
fn test_framebuffer_info_retina_2x() {
    let info = FramebufferInfo {
        addr: 0xE0000000,
        width: 3840,
        height: 2160,
        stride: 3840 * 4,
        bpp: 32,
    };
    assert_eq!(info.width, 1920 * 2);
    assert_eq!(info.height, 1080 * 2);
}

#[test]
fn test_framebuffer_info_5k_resolution() {
    let info = FramebufferInfo {
        addr: 0xE0000000,
        width: 5120,
        height: 2880,
        stride: 5120 * 4,
        bpp: 32,
    };
    assert_eq!(info.width * info.height, 14745600);
}

#[test]
fn test_framebuffer_info_bytes_per_pixel_32() {
    let info = FramebufferInfo {
        addr: 0xE0000000,
        width: 1920,
        height: 1080,
        stride: 7680,
        bpp: 32,
    };
    assert_eq!(info.bpp / 8, 4);
}

#[test]
fn test_framebuffer_info_ultrawide_21_9() {
    let info = FramebufferInfo {
        addr: 0xE0000000,
        width: 2560,
        height: 1080,
        stride: 2560 * 4,
        bpp: 32,
    };
    assert!(info.width > info.height * 2);
}

#[test]
fn test_framebuffer_info_square_display() {
    let info = FramebufferInfo {
        addr: 0xE0000000,
        width: 1024,
        height: 1024,
        stride: 4096,
        bpp: 32,
    };
    assert_eq!(info.width, info.height);
}

#[test]
fn test_framebuffer_info_minimum_dimensions() {
    let info = FramebufferInfo {
        addr: 0xE0000000,
        width: 1,
        height: 1,
        stride: 4,
        bpp: 32,
    };
    assert_eq!(info.width, 1);
    assert_eq!(info.height, 1);
}

#[test]
fn test_framebuffer_info_max_u32_dimensions() {
    let info = FramebufferInfo {
        addr: 0xE0000000,
        width: u32::MAX,
        height: u32::MAX,
        stride: u32::MAX,
        bpp: 32,
    };
    assert_eq!(info.width, u32::MAX);
    assert_eq!(info.height, u32::MAX);
}
