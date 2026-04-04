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

#[test]
fn test_pixel_format_x8r8g8b8_bytes() {
    assert_eq!(PixelFormat::X8R8G8B8.bytes_per_pixel(), 4);
}

#[test]
fn test_pixel_format_a8r8g8b8_bytes() {
    assert_eq!(PixelFormat::A8R8G8B8.bytes_per_pixel(), 4);
}

#[test]
fn test_pixel_format_r8g8b8_bytes() {
    assert_eq!(PixelFormat::R8G8B8.bytes_per_pixel(), 3);
}

#[test]
fn test_pixel_format_r5g6b5_bytes() {
    assert_eq!(PixelFormat::R5G6B5.bytes_per_pixel(), 2);
}

#[test]
fn test_pixel_format_x8r8g8b8_bits() {
    assert_eq!(PixelFormat::X8R8G8B8.bits_per_pixel(), 32);
}

#[test]
fn test_pixel_format_a8r8g8b8_bits() {
    assert_eq!(PixelFormat::A8R8G8B8.bits_per_pixel(), 32);
}

#[test]
fn test_pixel_format_r8g8b8_bits() {
    assert_eq!(PixelFormat::R8G8B8.bits_per_pixel(), 24);
}

#[test]
fn test_pixel_format_r5g6b5_bits() {
    assert_eq!(PixelFormat::R5G6B5.bits_per_pixel(), 16);
}

#[test]
fn test_pixel_format_equality() {
    assert_eq!(PixelFormat::X8R8G8B8, PixelFormat::X8R8G8B8);
    assert_ne!(PixelFormat::X8R8G8B8, PixelFormat::A8R8G8B8);
}

#[test]
fn test_pixel_format_copy() {
    let fmt1 = PixelFormat::R5G6B5;
    let fmt2 = fmt1;
    assert_eq!(fmt1, fmt2);
}

#[test]
fn test_pixel_format_clone() {
    let fmt1 = PixelFormat::R8G8B8;
    let fmt2 = fmt1.clone();
    assert_eq!(fmt1, fmt2);
}

#[test]
fn test_display_mode_new() {
    let mode = DisplayMode::new(1024, 768, 32);
    assert_eq!(mode.width, 1024);
    assert_eq!(mode.height, 768);
    assert_eq!(mode.bpp, 32);
}

#[test]
fn test_display_mode_pitch_32bpp() {
    let mode = DisplayMode::new(1024, 768, 32);
    assert_eq!(mode.pitch, 1024 * 4);
}

#[test]
fn test_display_mode_pitch_24bpp() {
    let mode = DisplayMode::new(1024, 768, 24);
    assert_eq!(mode.pitch, 1024 * 3);
}

#[test]
fn test_display_mode_pitch_16bpp() {
    let mode = DisplayMode::new(1024, 768, 16);
    assert_eq!(mode.pitch, 1024 * 2);
}

#[test]
fn test_display_mode_framebuffer_size_32bpp() {
    let mode = DisplayMode::new(1024, 768, 32);
    assert_eq!(mode.framebuffer_size(), 1024 * 768 * 4);
}

#[test]
fn test_display_mode_framebuffer_size_16bpp() {
    let mode = DisplayMode::new(640, 480, 16);
    assert_eq!(mode.framebuffer_size(), 640 * 480 * 2);
}

#[test]
fn test_display_mode_total_pixels() {
    let mode = DisplayMode::new(1024, 768, 32);
    assert_eq!(mode.total_pixels(), 1024 * 768);
}

#[test]
fn test_display_mode_total_pixels_1080p() {
    let mode = DisplayMode::new(1920, 1080, 32);
    assert_eq!(mode.total_pixels(), 1920 * 1080);
}

#[test]
fn test_display_mode_vga() {
    let mode = DisplayMode::new(640, 480, 32);
    assert_eq!(mode.width, 640);
    assert_eq!(mode.height, 480);
    assert_eq!(mode.total_pixels(), 307200);
}

#[test]
fn test_display_mode_svga() {
    let mode = DisplayMode::new(800, 600, 32);
    assert_eq!(mode.total_pixels(), 480000);
}

#[test]
fn test_display_mode_xga() {
    let mode = DisplayMode::new(1024, 768, 32);
    assert_eq!(mode.total_pixels(), 786432);
}

#[test]
fn test_display_mode_full_hd() {
    let mode = DisplayMode::new(1920, 1080, 32);
    assert_eq!(mode.framebuffer_size(), 1920 * 1080 * 4);
}

#[test]
fn test_display_mode_copy() {
    let mode1 = DisplayMode::new(1024, 768, 32);
    let mode2 = mode1;
    assert_eq!(mode1.width, mode2.width);
    assert_eq!(mode1.height, mode2.height);
}

#[test]
fn test_display_mode_clone() {
    let mode1 = DisplayMode::new(800, 600, 16);
    let mode2 = mode1.clone();
    assert_eq!(mode1.width, mode2.width);
    assert_eq!(mode1.bpp, mode2.bpp);
}

#[test]
fn test_display_mode_debug() {
    let mode = DisplayMode::new(640, 480, 32);
    let debug_str = format!("{:?}", mode);
    assert!(debug_str.contains("640"));
    assert!(debug_str.contains("480"));
    assert!(debug_str.contains("32"));
}

#[test]
fn test_pixel_format_debug() {
    let fmt = PixelFormat::X8R8G8B8;
    let debug_str = format!("{:?}", fmt);
    assert_eq!(debug_str, "X8R8G8B8");
}

#[test]
fn test_display_mode_framebuffer_size_matches_pitch_times_height() {
    let mode = DisplayMode::new(1280, 720, 32);
    assert_eq!(mode.framebuffer_size(), mode.pitch as usize * mode.height as usize);
}

#[test]
fn test_pixel_format_bits_matches_bytes_times_8() {
    let formats = [
        PixelFormat::X8R8G8B8,
        PixelFormat::A8R8G8B8,
        PixelFormat::R8G8B8,
        PixelFormat::R5G6B5,
    ];
    for fmt in formats {
        assert_eq!(fmt.bits_per_pixel(), fmt.bytes_per_pixel() * 8);
    }
}
