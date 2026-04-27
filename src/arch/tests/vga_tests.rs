// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::arch::x86_64::vga::console::Console;
use crate::arch::x86_64::vga::constants::*;
use crate::test::framework::TestResult;

pub(crate) fn test_vga_buffer_addr() -> TestResult {
    if VGA_BUFFER_ADDR != 0xB8000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_screen_width() -> TestResult {
    if SCREEN_WIDTH != 80 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_screen_height() -> TestResult {
    if SCREEN_HEIGHT != 25 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_screen_size() -> TestResult {
    if SCREEN_SIZE != SCREEN_WIDTH * SCREEN_HEIGHT {
        return TestResult::Fail;
    }
    if SCREEN_SIZE != 2000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_bytes_per_char() -> TestResult {
    if BYTES_PER_CHAR != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vga_buffer_size() -> TestResult {
    if VGA_BUFFER_SIZE != SCREEN_SIZE * BYTES_PER_CHAR {
        return TestResult::Fail;
    }
    if VGA_BUFFER_SIZE != 4000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_max_consoles() -> TestResult {
    if MAX_CONSOLES != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_scrollback_lines() -> TestResult {
    if SCROLLBACK_LINES != 200 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_color_values() -> TestResult {
    if Color::Black as u8 != 0 {
        return TestResult::Fail;
    }
    if Color::Blue as u8 != 1 {
        return TestResult::Fail;
    }
    if Color::Green as u8 != 2 {
        return TestResult::Fail;
    }
    if Color::Cyan as u8 != 3 {
        return TestResult::Fail;
    }
    if Color::Red as u8 != 4 {
        return TestResult::Fail;
    }
    if Color::Magenta as u8 != 5 {
        return TestResult::Fail;
    }
    if Color::Brown as u8 != 6 {
        return TestResult::Fail;
    }
    if Color::LightGray as u8 != 7 {
        return TestResult::Fail;
    }
    if Color::DarkGray as u8 != 8 {
        return TestResult::Fail;
    }
    if Color::LightBlue as u8 != 9 {
        return TestResult::Fail;
    }
    if Color::LightGreen as u8 != 10 {
        return TestResult::Fail;
    }
    if Color::LightCyan as u8 != 11 {
        return TestResult::Fail;
    }
    if Color::LightRed as u8 != 12 {
        return TestResult::Fail;
    }
    if Color::Pink as u8 != 13 {
        return TestResult::Fail;
    }
    if Color::Yellow as u8 != 14 {
        return TestResult::Fail;
    }
    if Color::White as u8 != 15 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_color_name() -> TestResult {
    if Color::Black.name() != "Black" {
        return TestResult::Fail;
    }
    if Color::Blue.name() != "Blue" {
        return TestResult::Fail;
    }
    if Color::Green.name() != "Green" {
        return TestResult::Fail;
    }
    if Color::Cyan.name() != "Cyan" {
        return TestResult::Fail;
    }
    if Color::Red.name() != "Red" {
        return TestResult::Fail;
    }
    if Color::Magenta.name() != "Magenta" {
        return TestResult::Fail;
    }
    if Color::Brown.name() != "Brown" {
        return TestResult::Fail;
    }
    if Color::LightGray.name() != "LightGray" {
        return TestResult::Fail;
    }
    if Color::DarkGray.name() != "DarkGray" {
        return TestResult::Fail;
    }
    if Color::LightBlue.name() != "LightBlue" {
        return TestResult::Fail;
    }
    if Color::LightGreen.name() != "LightGreen" {
        return TestResult::Fail;
    }
    if Color::LightCyan.name() != "LightCyan" {
        return TestResult::Fail;
    }
    if Color::LightRed.name() != "LightRed" {
        return TestResult::Fail;
    }
    if Color::Pink.name() != "Pink" {
        return TestResult::Fail;
    }
    if Color::Yellow.name() != "Yellow" {
        return TestResult::Fail;
    }
    if Color::White.name() != "White" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_color_code_new() -> TestResult {
    let cc = ColorCode::new(Color::White, Color::Black);
    if cc.foreground() != Color::White as u8 {
        return TestResult::Fail;
    }
    if cc.background() != Color::Black as u8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_color_code_with_blink() -> TestResult {
    let cc = ColorCode::with_blink(Color::White, Color::Black);
    if !cc.is_blinking() {
        return TestResult::Fail;
    }
    if cc.foreground() != Color::White as u8 {
        return TestResult::Fail;
    }
    if cc.background() != Color::Black as u8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_color_code_foreground() -> TestResult {
    let cc = ColorCode::new(Color::Yellow, Color::Blue);
    if cc.foreground() != 14 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_color_code_background() -> TestResult {
    let cc = ColorCode::new(Color::Yellow, Color::Blue);
    if cc.background() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_color_code_is_blinking() -> TestResult {
    let blink = ColorCode::with_blink(Color::White, Color::Black);
    let no_blink = ColorCode::new(Color::White, Color::Black);
    if !blink.is_blinking() {
        return TestResult::Fail;
    }
    if no_blink.is_blinking() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_color_code_value() -> TestResult {
    let cc = ColorCode::new(Color::LightGray, Color::Black);
    if cc.value() != 0x07 {
        return TestResult::Fail;
    }
    let cc2 = ColorCode::new(Color::White, Color::Blue);
    if cc2.value() != 0x1F {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_color_code_default() -> TestResult {
    let cc = ColorCode::default();
    if cc.foreground() != Color::LightGray as u8 {
        return TestResult::Fail;
    }
    if cc.background() != Color::Black as u8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_color_code_copy() -> TestResult {
    let cc1 = ColorCode::new(Color::Red, Color::White);
    let cc2 = cc1;
    if cc1 != cc2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_color_code_eq() -> TestResult {
    let cc1 = ColorCode::new(Color::Green, Color::Black);
    let cc2 = ColorCode::new(Color::Green, Color::Black);
    let cc3 = ColorCode::new(Color::Red, Color::Black);
    if cc1 != cc2 {
        return TestResult::Fail;
    }
    if cc1 == cc3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_screen_char_new() -> TestResult {
    let sc = ScreenChar::new(b'A', ColorCode::default());
    if sc.character != b'A' {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_screen_char_blank() -> TestResult {
    let sc = ScreenChar::blank(ColorCode::default());
    if sc.character != b' ' {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_screen_char_as_u16() -> TestResult {
    let cc = ColorCode::new(Color::LightGray, Color::Black);
    let sc = ScreenChar::new(b'A', cc);
    let value = sc.as_u16();
    if value & 0xFF != b'A' as u16 {
        return TestResult::Fail;
    }
    if (value >> 8) as u8 != cc.value() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_screen_char_default() -> TestResult {
    let sc = ScreenChar::default();
    if sc.character != b' ' {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_screen_char_copy() -> TestResult {
    let sc1 = ScreenChar::new(b'X', ColorCode::default());
    let sc2 = sc1;
    if sc1 != sc2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_screen_char_eq() -> TestResult {
    let sc1 = ScreenChar::new(b'Y', ColorCode::default());
    let sc2 = ScreenChar::new(b'Y', ColorCode::default());
    let sc3 = ScreenChar::new(b'Z', ColorCode::default());
    if sc1 != sc2 {
        return TestResult::Fail;
    }
    if sc1 == sc3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_console_new() -> TestResult {
    let console = Console::new();
    if console.row != 0 {
        return TestResult::Fail;
    }
    if console.col != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_console_clear() -> TestResult {
    let mut console = Console::new();
    console.row = 10;
    console.col = 20;
    console.clear();
    if console.row != 0 {
        return TestResult::Fail;
    }
    if console.col != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_console_write_byte() -> TestResult {
    let mut console = Console::new();
    console.write_byte(b'H');
    if console.col != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_console_write_byte_newline() -> TestResult {
    let mut console = Console::new();
    console.write_byte(b'\n');
    if console.row != 1 {
        return TestResult::Fail;
    }
    if console.col != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_console_write_byte_carriage_return() -> TestResult {
    let mut console = Console::new();
    console.col = 10;
    console.write_byte(b'\r');
    if console.col != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_console_write_byte_tab() -> TestResult {
    let mut console = Console::new();
    console.write_byte(b'\t');
    if console.col != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_console_write_byte_backspace() -> TestResult {
    let mut console = Console::new();
    console.write_byte(b'A');
    console.write_byte(0x08);
    if console.col != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_console_write_multiple_bytes() -> TestResult {
    let mut console = Console::new();
    for c in b"Hello" {
        console.write_byte(*c);
    }
    if console.col != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_console_set_color() -> TestResult {
    let mut console = Console::new();
    console.set_color(Color::Red, Color::White);
    console.write_byte(b'X');
    if console.col != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_console_wrap_line() -> TestResult {
    let mut console = Console::new();
    for _ in 0..SCREEN_WIDTH {
        console.write_byte(b'A');
    }
    console.write_byte(b'B');
    if console.row != 1 {
        return TestResult::Fail;
    }
    if console.col != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_console_scroll() -> TestResult {
    let mut console = Console::new();
    for _ in 0..SCREEN_HEIGHT + 1 {
        console.write_byte(b'\n');
    }
    if console.row != SCREEN_HEIGHT - 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_color_clone() -> TestResult {
    let c1 = Color::Red;
    let c2 = c1.clone();
    if c1 != c2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_screen_char_clone() -> TestResult {
    let sc1 = ScreenChar::new(b'Z', ColorCode::default());
    let sc2 = sc1.clone();
    if sc1 != sc2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_color_code_background_max() -> TestResult {
    let cc = ColorCode::new(Color::White, Color::LightGray);
    if cc.background() != 7 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_screen_position_calculation() -> TestResult {
    let row = 10;
    let col = 40;
    let pos = row * SCREEN_WIDTH + col;
    if pos != 840 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_vga_address_calculation() -> TestResult {
    let row = 5;
    let col = 10;
    let offset = (row * SCREEN_WIDTH + col) * BYTES_PER_CHAR;
    let addr = VGA_BUFFER_ADDR + offset;
    if addr != 0xB8000 + 820 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
