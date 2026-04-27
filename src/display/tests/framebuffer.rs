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
use crate::test::framework::TestResult;

pub(crate) fn test_framebuffer_info_creation() -> TestResult {
    let info = FramebufferInfo { addr: 0xB8000, width: 1920, height: 1080, stride: 7680, bpp: 32 };
    if info.addr != 0xB8000 {
        return TestResult::Fail;
    }
    if info.width != 1920 {
        return TestResult::Fail;
    }
    if info.height != 1080 {
        return TestResult::Fail;
    }
    if info.stride != 7680 {
        return TestResult::Fail;
    }
    if info.bpp != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_framebuffer_info_clone() -> TestResult {
    let info = FramebufferInfo { addr: 0xFD000000, width: 800, height: 600, stride: 3200, bpp: 32 };
    let cloned = info.clone();
    if info.addr != cloned.addr {
        return TestResult::Fail;
    }
    if info.width != cloned.width {
        return TestResult::Fail;
    }
    if info.height != cloned.height {
        return TestResult::Fail;
    }
    if info.stride != cloned.stride {
        return TestResult::Fail;
    }
    if info.bpp != cloned.bpp {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_framebuffer_info_copy() -> TestResult {
    let info =
        FramebufferInfo { addr: 0xE0000000, width: 1024, height: 768, stride: 4096, bpp: 32 };
    let copied = info;
    if info.addr != copied.addr {
        return TestResult::Fail;
    }
    if info.width != copied.width {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_framebuffer_info_debug() -> TestResult {
    let info = FramebufferInfo { addr: 0x12345678, width: 640, height: 480, stride: 2560, bpp: 32 };
    let debug = alloc::format!("{:?}", info);
    if !debug.contains("FramebufferInfo") {
        return TestResult::Fail;
    }
    if !debug.contains("addr") {
        return TestResult::Fail;
    }
    if !debug.contains("width") {
        return TestResult::Fail;
    }
    if !debug.contains("height") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_framebuffer_info_standard_resolutions() -> TestResult {
    let hd =
        FramebufferInfo { addr: 0x10000000, width: 1920, height: 1080, stride: 1920 * 4, bpp: 32 };
    if hd.width * hd.height != 2073600 {
        return TestResult::Fail;
    }

    let fhd_plus =
        FramebufferInfo { addr: 0x10000000, width: 2560, height: 1440, stride: 2560 * 4, bpp: 32 };
    if fhd_plus.width * fhd_plus.height != 3686400 {
        return TestResult::Fail;
    }

    let uhd =
        FramebufferInfo { addr: 0x10000000, width: 3840, height: 2160, stride: 3840 * 4, bpp: 32 };
    if uhd.width * uhd.height != 8294400 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_framebuffer_info_stride_calculation() -> TestResult {
    let info =
        FramebufferInfo { addr: 0x10000000, width: 1920, height: 1080, stride: 1920 * 4, bpp: 32 };
    if info.stride != info.width * (info.bpp / 8) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_framebuffer_info_stride_with_padding() -> TestResult {
    let info =
        FramebufferInfo { addr: 0x10000000, width: 1920, height: 1080, stride: 8192, bpp: 32 };
    if info.stride < info.width * (info.bpp / 8) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_framebuffer_info_vga_resolution() -> TestResult {
    let vga = FramebufferInfo { addr: 0xA0000, width: 640, height: 480, stride: 640 * 4, bpp: 32 };
    if vga.width != 640 {
        return TestResult::Fail;
    }
    if vga.height != 480 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_framebuffer_info_svga_resolution() -> TestResult {
    let svga =
        FramebufferInfo { addr: 0xE0000000, width: 800, height: 600, stride: 800 * 4, bpp: 32 };
    if svga.width != 800 {
        return TestResult::Fail;
    }
    if svga.height != 600 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_framebuffer_info_xga_resolution() -> TestResult {
    let xga =
        FramebufferInfo { addr: 0xE0000000, width: 1024, height: 768, stride: 1024 * 4, bpp: 32 };
    if xga.width != 1024 {
        return TestResult::Fail;
    }
    if xga.height != 768 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_framebuffer_info_sxga_resolution() -> TestResult {
    let sxga =
        FramebufferInfo { addr: 0xE0000000, width: 1280, height: 1024, stride: 1280 * 4, bpp: 32 };
    if sxga.width != 1280 {
        return TestResult::Fail;
    }
    if sxga.height != 1024 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_framebuffer_info_bpp_24() -> TestResult {
    let info =
        FramebufferInfo { addr: 0xE0000000, width: 1920, height: 1080, stride: 1920 * 3, bpp: 24 };
    if info.bpp != 24 {
        return TestResult::Fail;
    }
    if info.stride != info.width * 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_framebuffer_info_bpp_16() -> TestResult {
    let info =
        FramebufferInfo { addr: 0xE0000000, width: 1920, height: 1080, stride: 1920 * 2, bpp: 16 };
    if info.bpp != 16 {
        return TestResult::Fail;
    }
    if info.stride != info.width * 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_framebuffer_info_bpp_8() -> TestResult {
    let info = FramebufferInfo { addr: 0xE0000000, width: 320, height: 200, stride: 320, bpp: 8 };
    if info.bpp != 8 {
        return TestResult::Fail;
    }
    if info.stride != info.width {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_framebuffer_info_large_address() -> TestResult {
    let info = FramebufferInfo {
        addr: 0xFFFF_FFFF_FFFF_0000,
        width: 1920,
        height: 1080,
        stride: 7680,
        bpp: 32,
    };
    if info.addr != 0xFFFF_FFFF_FFFF_0000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_framebuffer_info_buffer_size() -> TestResult {
    let info =
        FramebufferInfo { addr: 0xE0000000, width: 1920, height: 1080, stride: 7680, bpp: 32 };
    let buffer_size = (info.stride as u64) * (info.height as u64);
    if buffer_size != 8294400 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_framebuffer_info_pixel_offset() -> TestResult {
    let info =
        FramebufferInfo { addr: 0xE0000000, width: 1920, height: 1080, stride: 7680, bpp: 32 };
    let x = 100u32;
    let y = 200u32;
    let offset = (y as u64) * (info.stride as u64) + (x as u64) * ((info.bpp / 8) as u64);
    if offset != 200 * 7680 + 100 * 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_framebuffer_info_row_offset() -> TestResult {
    let info =
        FramebufferInfo { addr: 0xE0000000, width: 1920, height: 1080, stride: 7680, bpp: 32 };
    let row_offset = info.stride as u64;
    if row_offset != 7680 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_register_framebuffer_invalid_address_zero() -> TestResult {
    let info = FramebufferInfo { addr: 0, width: 1920, height: 1080, stride: 7680, bpp: 32 };
    let result = register_framebuffer(info);
    if !result.is_err() {
        return TestResult::Fail;
    }
    if result.unwrap_err() != DisplayError::InvalidAddress {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_register_framebuffer_invalid_width_zero() -> TestResult {
    let info = FramebufferInfo { addr: 0xE0000000, width: 0, height: 1080, stride: 7680, bpp: 32 };
    let result = register_framebuffer(info);
    if !result.is_err() {
        return TestResult::Fail;
    }
    if result.unwrap_err() != DisplayError::InvalidFormat {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_register_framebuffer_invalid_height_zero() -> TestResult {
    let info = FramebufferInfo { addr: 0xE0000000, width: 1920, height: 0, stride: 7680, bpp: 32 };
    let result = register_framebuffer(info);
    if !result.is_err() {
        return TestResult::Fail;
    }
    if result.unwrap_err() != DisplayError::InvalidFormat {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_register_framebuffer_invalid_both_dimensions_zero() -> TestResult {
    let info = FramebufferInfo { addr: 0xE0000000, width: 0, height: 0, stride: 0, bpp: 32 };
    let result = register_framebuffer(info);
    if !result.is_err() {
        return TestResult::Fail;
    }
    if result.unwrap_err() != DisplayError::InvalidFormat {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_framebuffer_info_widescreen_16_9() -> TestResult {
    let info =
        FramebufferInfo { addr: 0xE0000000, width: 1920, height: 1080, stride: 7680, bpp: 32 };
    let aspect_width = info.width / 120;
    let aspect_height = info.height / 120;
    if aspect_width != 16 {
        return TestResult::Fail;
    }
    if aspect_height != 9 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_framebuffer_info_widescreen_16_10() -> TestResult {
    let info =
        FramebufferInfo { addr: 0xE0000000, width: 1920, height: 1200, stride: 7680, bpp: 32 };
    let aspect_width = info.width / 120;
    let aspect_height = info.height / 120;
    if aspect_width != 16 {
        return TestResult::Fail;
    }
    if aspect_height != 10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_framebuffer_info_standard_4_3() -> TestResult {
    let info =
        FramebufferInfo { addr: 0xE0000000, width: 1024, height: 768, stride: 4096, bpp: 32 };
    let aspect_width = info.width / 256;
    let aspect_height = info.height / 256;
    if aspect_width != 4 {
        return TestResult::Fail;
    }
    if aspect_height != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_framebuffer_info_retina_2x() -> TestResult {
    let info =
        FramebufferInfo { addr: 0xE0000000, width: 3840, height: 2160, stride: 3840 * 4, bpp: 32 };
    if info.width != 1920 * 2 {
        return TestResult::Fail;
    }
    if info.height != 1080 * 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_framebuffer_info_5k_resolution() -> TestResult {
    let info =
        FramebufferInfo { addr: 0xE0000000, width: 5120, height: 2880, stride: 5120 * 4, bpp: 32 };
    if info.width * info.height != 14745600 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_framebuffer_info_bytes_per_pixel_32() -> TestResult {
    let info =
        FramebufferInfo { addr: 0xE0000000, width: 1920, height: 1080, stride: 7680, bpp: 32 };
    if info.bpp / 8 != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_framebuffer_info_ultrawide_21_9() -> TestResult {
    let info =
        FramebufferInfo { addr: 0xE0000000, width: 2560, height: 1080, stride: 2560 * 4, bpp: 32 };
    if info.width <= info.height * 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_framebuffer_info_square_display() -> TestResult {
    let info =
        FramebufferInfo { addr: 0xE0000000, width: 1024, height: 1024, stride: 4096, bpp: 32 };
    if info.width != info.height {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_framebuffer_info_minimum_dimensions() -> TestResult {
    let info = FramebufferInfo { addr: 0xE0000000, width: 1, height: 1, stride: 4, bpp: 32 };
    if info.width != 1 {
        return TestResult::Fail;
    }
    if info.height != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_framebuffer_info_max_u32_dimensions() -> TestResult {
    let info = FramebufferInfo {
        addr: 0xE0000000,
        width: u32::MAX,
        height: u32::MAX,
        stride: u32::MAX,
        bpp: 32,
    };
    if info.width != u32::MAX {
        return TestResult::Fail;
    }
    if info.height != u32::MAX {
        return TestResult::Fail;
    }
    TestResult::Pass
}
