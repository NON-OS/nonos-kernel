use crate::arch::x86_64::vga::constants::*;
use crate::arch::x86_64::vga::console::Console;

#[test]
fn test_vga_buffer_addr() {
    assert_eq!(VGA_BUFFER_ADDR, 0xB8000);
}

#[test]
fn test_screen_width() {
    assert_eq!(SCREEN_WIDTH, 80);
}

#[test]
fn test_screen_height() {
    assert_eq!(SCREEN_HEIGHT, 25);
}

#[test]
fn test_screen_size() {
    assert_eq!(SCREEN_SIZE, SCREEN_WIDTH * SCREEN_HEIGHT);
    assert_eq!(SCREEN_SIZE, 2000);
}

#[test]
fn test_bytes_per_char() {
    assert_eq!(BYTES_PER_CHAR, 2);
}

#[test]
fn test_vga_buffer_size() {
    assert_eq!(VGA_BUFFER_SIZE, SCREEN_SIZE * BYTES_PER_CHAR);
    assert_eq!(VGA_BUFFER_SIZE, 4000);
}

#[test]
fn test_max_consoles() {
    assert_eq!(MAX_CONSOLES, 4);
}

#[test]
fn test_scrollback_lines() {
    assert_eq!(SCROLLBACK_LINES, 200);
}

#[test]
fn test_color_values() {
    assert_eq!(Color::Black as u8, 0);
    assert_eq!(Color::Blue as u8, 1);
    assert_eq!(Color::Green as u8, 2);
    assert_eq!(Color::Cyan as u8, 3);
    assert_eq!(Color::Red as u8, 4);
    assert_eq!(Color::Magenta as u8, 5);
    assert_eq!(Color::Brown as u8, 6);
    assert_eq!(Color::LightGray as u8, 7);
    assert_eq!(Color::DarkGray as u8, 8);
    assert_eq!(Color::LightBlue as u8, 9);
    assert_eq!(Color::LightGreen as u8, 10);
    assert_eq!(Color::LightCyan as u8, 11);
    assert_eq!(Color::LightRed as u8, 12);
    assert_eq!(Color::Pink as u8, 13);
    assert_eq!(Color::Yellow as u8, 14);
    assert_eq!(Color::White as u8, 15);
}

#[test]
fn test_color_name() {
    assert_eq!(Color::Black.name(), "Black");
    assert_eq!(Color::Blue.name(), "Blue");
    assert_eq!(Color::Green.name(), "Green");
    assert_eq!(Color::Cyan.name(), "Cyan");
    assert_eq!(Color::Red.name(), "Red");
    assert_eq!(Color::Magenta.name(), "Magenta");
    assert_eq!(Color::Brown.name(), "Brown");
    assert_eq!(Color::LightGray.name(), "LightGray");
    assert_eq!(Color::DarkGray.name(), "DarkGray");
    assert_eq!(Color::LightBlue.name(), "LightBlue");
    assert_eq!(Color::LightGreen.name(), "LightGreen");
    assert_eq!(Color::LightCyan.name(), "LightCyan");
    assert_eq!(Color::LightRed.name(), "LightRed");
    assert_eq!(Color::Pink.name(), "Pink");
    assert_eq!(Color::Yellow.name(), "Yellow");
    assert_eq!(Color::White.name(), "White");
}

#[test]
fn test_color_code_new() {
    let cc = ColorCode::new(Color::White, Color::Black);
    assert_eq!(cc.foreground(), Color::White as u8);
    assert_eq!(cc.background(), Color::Black as u8);
}

#[test]
fn test_color_code_with_blink() {
    let cc = ColorCode::with_blink(Color::White, Color::Black);
    assert!(cc.is_blinking());
    assert_eq!(cc.foreground(), Color::White as u8);
    assert_eq!(cc.background(), Color::Black as u8);
}

#[test]
fn test_color_code_foreground() {
    let cc = ColorCode::new(Color::Yellow, Color::Blue);
    assert_eq!(cc.foreground(), 14);
}

#[test]
fn test_color_code_background() {
    let cc = ColorCode::new(Color::Yellow, Color::Blue);
    assert_eq!(cc.background(), 1);
}

#[test]
fn test_color_code_is_blinking() {
    let blink = ColorCode::with_blink(Color::White, Color::Black);
    let no_blink = ColorCode::new(Color::White, Color::Black);
    assert!(blink.is_blinking());
    assert!(!no_blink.is_blinking());
}

#[test]
fn test_color_code_value() {
    let cc = ColorCode::new(Color::LightGray, Color::Black);
    assert_eq!(cc.value(), 0x07);

    let cc2 = ColorCode::new(Color::White, Color::Blue);
    assert_eq!(cc2.value(), 0x1F);
}

#[test]
fn test_color_code_default() {
    let cc = ColorCode::default();
    assert_eq!(cc.foreground(), Color::LightGray as u8);
    assert_eq!(cc.background(), Color::Black as u8);
}

#[test]
fn test_color_code_copy() {
    let cc1 = ColorCode::new(Color::Red, Color::White);
    let cc2 = cc1;
    assert_eq!(cc1, cc2);
}

#[test]
fn test_color_code_eq() {
    let cc1 = ColorCode::new(Color::Green, Color::Black);
    let cc2 = ColorCode::new(Color::Green, Color::Black);
    let cc3 = ColorCode::new(Color::Red, Color::Black);
    assert_eq!(cc1, cc2);
    assert_ne!(cc1, cc3);
}

#[test]
fn test_screen_char_new() {
    let sc = ScreenChar::new(b'A', ColorCode::default());
    assert_eq!(sc.character, b'A');
}

#[test]
fn test_screen_char_blank() {
    let sc = ScreenChar::blank(ColorCode::default());
    assert_eq!(sc.character, b' ');
}

#[test]
fn test_screen_char_as_u16() {
    let cc = ColorCode::new(Color::LightGray, Color::Black);
    let sc = ScreenChar::new(b'A', cc);
    let value = sc.as_u16();
    assert_eq!(value & 0xFF, b'A' as u16);
    assert_eq!((value >> 8) as u8, cc.value());
}

#[test]
fn test_screen_char_default() {
    let sc = ScreenChar::default();
    assert_eq!(sc.character, b' ');
}

#[test]
fn test_screen_char_copy() {
    let sc1 = ScreenChar::new(b'X', ColorCode::default());
    let sc2 = sc1;
    assert_eq!(sc1, sc2);
}

#[test]
fn test_screen_char_eq() {
    let sc1 = ScreenChar::new(b'Y', ColorCode::default());
    let sc2 = ScreenChar::new(b'Y', ColorCode::default());
    let sc3 = ScreenChar::new(b'Z', ColorCode::default());
    assert_eq!(sc1, sc2);
    assert_ne!(sc1, sc3);
}

#[test]
fn test_console_new() {
    let console = Console::new();
    assert_eq!(console.row, 0);
    assert_eq!(console.col, 0);
}

#[test]
fn test_console_clear() {
    let mut console = Console::new();
    console.row = 10;
    console.col = 20;
    console.clear();
    assert_eq!(console.row, 0);
    assert_eq!(console.col, 0);
}

#[test]
fn test_console_write_byte() {
    let mut console = Console::new();
    console.write_byte(b'H');
    assert_eq!(console.col, 1);
}

#[test]
fn test_console_write_byte_newline() {
    let mut console = Console::new();
    console.write_byte(b'\n');
    assert_eq!(console.row, 1);
    assert_eq!(console.col, 0);
}

#[test]
fn test_console_write_byte_carriage_return() {
    let mut console = Console::new();
    console.col = 10;
    console.write_byte(b'\r');
    assert_eq!(console.col, 0);
}

#[test]
fn test_console_write_byte_tab() {
    let mut console = Console::new();
    console.write_byte(b'\t');
    assert_eq!(console.col, 4);
}

#[test]
fn test_console_write_byte_backspace() {
    let mut console = Console::new();
    console.write_byte(b'A');
    console.write_byte(0x08);
    assert_eq!(console.col, 0);
}

#[test]
fn test_console_write_multiple_bytes() {
    let mut console = Console::new();
    for c in b"Hello" {
        console.write_byte(*c);
    }
    assert_eq!(console.col, 5);
}

#[test]
fn test_console_set_color() {
    let mut console = Console::new();
    console.set_color(Color::Red, Color::White);
    console.write_byte(b'X');
    assert_eq!(console.col, 1);
}

#[test]
fn test_console_wrap_line() {
    let mut console = Console::new();
    for _ in 0..SCREEN_WIDTH {
        console.write_byte(b'A');
    }
    console.write_byte(b'B');
    assert_eq!(console.row, 1);
    assert_eq!(console.col, 1);
}

#[test]
fn test_console_scroll() {
    let mut console = Console::new();
    for _ in 0..SCREEN_HEIGHT + 1 {
        console.write_byte(b'\n');
    }
    assert_eq!(console.row, SCREEN_HEIGHT - 1);
}

#[test]
fn test_color_clone() {
    let c1 = Color::Red;
    let c2 = c1.clone();
    assert_eq!(c1, c2);
}

#[test]
fn test_screen_char_clone() {
    let sc1 = ScreenChar::new(b'Z', ColorCode::default());
    let sc2 = sc1.clone();
    assert_eq!(sc1, sc2);
}

#[test]
fn test_color_code_background_max() {
    let cc = ColorCode::new(Color::White, Color::LightGray);
    assert_eq!(cc.background(), 7);
}

#[test]
fn test_screen_position_calculation() {
    let row = 10;
    let col = 40;
    let pos = row * SCREEN_WIDTH + col;
    assert_eq!(pos, 840);
}

#[test]
fn test_vga_address_calculation() {
    let row = 5;
    let col = 10;
    let offset = (row * SCREEN_WIDTH + col) * BYTES_PER_CHAR;
    let addr = VGA_BUFFER_ADDR + offset;
    assert_eq!(addr, 0xB8000 + 820);
}
