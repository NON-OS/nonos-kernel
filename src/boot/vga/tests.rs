use super::colors;
use super::output::{buffer_size, VGA_HEIGHT, VGA_WIDTH};

#[test]
fn test_color_constants() {
    assert_eq!(colors::BLACK, 0x00);
    assert_eq!(colors::WHITE, 0x0F);
    assert_eq!(colors::LIGHT_CYAN, 0x0B);
    assert_eq!(colors::RED, 0x04);
    assert_eq!(colors::LIGHT_GREEN, 0x0A);
}

#[test]
fn test_vga_dimensions() {
    assert_eq!(VGA_WIDTH, 80);
    assert_eq!(VGA_HEIGHT, 25);
    assert_eq!(VGA_WIDTH * VGA_HEIGHT, 2000);
}

#[test]
fn test_buffer_size() {
    assert_eq!(buffer_size(), VGA_WIDTH * VGA_HEIGHT * 2);
    assert_eq!(buffer_size(), 4000);
}

#[test]
fn test_make_attr() {
    assert_eq!(colors::make_attr(colors::WHITE, colors::BLACK), 0x0F);
    assert_eq!(colors::make_attr(colors::BLACK, colors::WHITE), 0xF0);
    assert_eq!(colors::make_attr(colors::LIGHT_CYAN, colors::BLUE), 0x1B);
}

#[test]
fn test_fg_bg_extraction() {
    let attr = colors::make_attr(colors::YELLOW, colors::BLUE);
    assert_eq!(colors::fg_color(attr), colors::YELLOW);
    assert_eq!(colors::bg_color(attr), colors::BLUE);
}
