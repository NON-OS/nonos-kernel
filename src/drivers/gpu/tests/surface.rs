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

use crate::drivers::gpu::surface::{DisplayMode, PixelFormat};
use crate::test::framework::TestResult;

pub(crate) fn test_pixel_format_x8r8g8b8_bytes() -> TestResult {
    if PixelFormat::X8R8G8B8.bytes_per_pixel() != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pixel_format_a8r8g8b8_bytes() -> TestResult {
    if PixelFormat::A8R8G8B8.bytes_per_pixel() != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pixel_format_r8g8b8_bytes() -> TestResult {
    if PixelFormat::R8G8B8.bytes_per_pixel() != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pixel_format_r5g6b5_bytes() -> TestResult {
    if PixelFormat::R5G6B5.bytes_per_pixel() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pixel_format_x8r8g8b8_bits() -> TestResult {
    if PixelFormat::X8R8G8B8.bits_per_pixel() != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pixel_format_a8r8g8b8_bits() -> TestResult {
    if PixelFormat::A8R8G8B8.bits_per_pixel() != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pixel_format_r8g8b8_bits() -> TestResult {
    if PixelFormat::R8G8B8.bits_per_pixel() != 24 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pixel_format_r5g6b5_bits() -> TestResult {
    if PixelFormat::R5G6B5.bits_per_pixel() != 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pixel_format_equality() -> TestResult {
    if PixelFormat::X8R8G8B8 != PixelFormat::X8R8G8B8 {
        return TestResult::Fail;
    }
    if PixelFormat::X8R8G8B8 == PixelFormat::A8R8G8B8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pixel_format_copy() -> TestResult {
    let fmt1 = PixelFormat::R5G6B5;
    let fmt2 = fmt1;
    if fmt1 != fmt2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pixel_format_clone() -> TestResult {
    let fmt1 = PixelFormat::R8G8B8;
    let fmt2 = fmt1.clone();
    if fmt1 != fmt2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_display_mode_new() -> TestResult {
    let mode = DisplayMode::new(1024, 768, 32);
    if mode.width != 1024 {
        return TestResult::Fail;
    }
    if mode.height != 768 {
        return TestResult::Fail;
    }
    if mode.bpp != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_display_mode_pitch_32bpp() -> TestResult {
    let mode = DisplayMode::new(1024, 768, 32);
    if mode.pitch != 1024 * 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_display_mode_pitch_24bpp() -> TestResult {
    let mode = DisplayMode::new(1024, 768, 24);
    if mode.pitch != 1024 * 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_display_mode_pitch_16bpp() -> TestResult {
    let mode = DisplayMode::new(1024, 768, 16);
    if mode.pitch != 1024 * 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_display_mode_framebuffer_size_32bpp() -> TestResult {
    let mode = DisplayMode::new(1024, 768, 32);
    if mode.framebuffer_size() != 1024 * 768 * 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_display_mode_framebuffer_size_16bpp() -> TestResult {
    let mode = DisplayMode::new(640, 480, 16);
    if mode.framebuffer_size() != 640 * 480 * 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_display_mode_total_pixels() -> TestResult {
    let mode = DisplayMode::new(1024, 768, 32);
    if mode.total_pixels() != 1024 * 768 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_display_mode_total_pixels_1080p() -> TestResult {
    let mode = DisplayMode::new(1920, 1080, 32);
    if mode.total_pixels() != 1920 * 1080 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_display_mode_vga() -> TestResult {
    let mode = DisplayMode::new(640, 480, 32);
    if mode.width != 640 {
        return TestResult::Fail;
    }
    if mode.height != 480 {
        return TestResult::Fail;
    }
    if mode.total_pixels() != 307200 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_display_mode_svga() -> TestResult {
    let mode = DisplayMode::new(800, 600, 32);
    if mode.total_pixels() != 480000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_display_mode_xga() -> TestResult {
    let mode = DisplayMode::new(1024, 768, 32);
    if mode.total_pixels() != 786432 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_display_mode_full_hd() -> TestResult {
    let mode = DisplayMode::new(1920, 1080, 32);
    if mode.framebuffer_size() != 1920 * 1080 * 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_display_mode_copy() -> TestResult {
    let mode1 = DisplayMode::new(1024, 768, 32);
    let mode2 = mode1;
    if mode1.width != mode2.width {
        return TestResult::Fail;
    }
    if mode1.height != mode2.height {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_display_mode_clone() -> TestResult {
    let mode1 = DisplayMode::new(800, 600, 16);
    let mode2 = mode1.clone();
    if mode1.width != mode2.width {
        return TestResult::Fail;
    }
    if mode1.bpp != mode2.bpp {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_display_mode_debug() -> TestResult {
    use core::fmt::Write;
    let mode = DisplayMode::new(640, 480, 32);
    let mut buf = [0u8; 128];
    let mut writer = crate::test::framework::ArrayWriter::new(&mut buf);
    let _ = write!(writer, "{:?}", mode);
    let debug_str = writer.as_str();
    if !debug_str.contains("640") {
        return TestResult::Fail;
    }
    if !debug_str.contains("480") {
        return TestResult::Fail;
    }
    if !debug_str.contains("32") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pixel_format_debug() -> TestResult {
    use core::fmt::Write;
    let fmt = PixelFormat::X8R8G8B8;
    let mut buf = [0u8; 64];
    let mut writer = crate::test::framework::ArrayWriter::new(&mut buf);
    let _ = write!(writer, "{:?}", fmt);
    let debug_str = writer.as_str();
    if debug_str != "X8R8G8B8" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_display_mode_framebuffer_size_matches_pitch_times_height() -> TestResult {
    let mode = DisplayMode::new(1280, 720, 32);
    if mode.framebuffer_size() != mode.pitch as usize * mode.height as usize {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pixel_format_bits_matches_bytes_times_8() -> TestResult {
    let formats =
        [PixelFormat::X8R8G8B8, PixelFormat::A8R8G8B8, PixelFormat::R8G8B8, PixelFormat::R5G6B5];
    for fmt in formats {
        if fmt.bits_per_pixel() != fmt.bytes_per_pixel() * 8 {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}
