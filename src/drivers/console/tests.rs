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

//! Console driver unit tests.

use super::*;
use super::types::*;
use super::ansi::*;

#[test]
fn test_color_values() {
    assert_eq!(Color::Black as u8, 0x0);
    assert_eq!(Color::Blue as u8, 0x1);
    assert_eq!(Color::Green as u8, 0x2);
    assert_eq!(Color::Cyan as u8, 0x3);
    assert_eq!(Color::Red as u8, 0x4);
    assert_eq!(Color::Magenta as u8, 0x5);
    assert_eq!(Color::Brown as u8, 0x6);
    assert_eq!(Color::LightGrey as u8, 0x7);
    assert_eq!(Color::DarkGrey as u8, 0x8);
    assert_eq!(Color::LightBlue as u8, 0x9);
    assert_eq!(Color::LightGreen as u8, 0xA);
    assert_eq!(Color::LightCyan as u8, 0xB);
    assert_eq!(Color::LightRed as u8, 0xC);
    assert_eq!(Color::Pink as u8, 0xD);
    assert_eq!(Color::Yellow as u8, 0xE);
    assert_eq!(Color::White as u8, 0xF);
}

#[test]
fn test_color_default() {
    let color: Color = Color::default();
    assert_eq!(color, Color::LightGrey);
}

#[test]
fn test_color_from_ansi() {
    assert_eq!(Color::from_ansi(0), Color::Black);
    assert_eq!(Color::from_ansi(1), Color::Red);
    assert_eq!(Color::from_ansi(2), Color::Green);
    assert_eq!(Color::from_ansi(3), Color::Brown);
    assert_eq!(Color::from_ansi(4), Color::Blue);
    assert_eq!(Color::from_ansi(5), Color::Magenta);
    assert_eq!(Color::from_ansi(6), Color::Cyan);
    assert_eq!(Color::from_ansi(7), Color::LightGrey);
    assert_eq!(Color::from_ansi(8), Color::LightGrey);
}

#[test]
fn test_make_color() {
    assert_eq!(make_color(Color::LightGrey, Color::Black), 0x07);
    assert_eq!(make_color(Color::White, Color::Blue), 0x1F);
    assert_eq!(make_color(Color::Red, Color::Green), 0x24);
    assert_eq!(make_color(Color::Yellow, Color::Cyan), 0x3E);
}

#[test]
fn test_fg_from_attr() {
    assert_eq!(fg_from_attr(0x07), 0x07);
    assert_eq!(fg_from_attr(0x1F), 0x0F);
    assert_eq!(fg_from_attr(0x24), 0x04);
    assert_eq!(fg_from_attr(0xAB), 0x0B);
}

#[test]
fn test_bg_from_attr() {
    assert_eq!(bg_from_attr(0x07), 0x00);
    assert_eq!(bg_from_attr(0x1F), 0x01);
    assert_eq!(bg_from_attr(0x24), 0x02);
    assert_eq!(bg_from_attr(0xAB), 0x0A);
}

#[test]
fn test_set_fg() {
    let attr = make_color(Color::LightGrey, Color::Blue);
    let new_attr = set_fg(attr, Color::Red);
    assert_eq!(fg_from_attr(new_attr), Color::Red as u8);
    assert_eq!(bg_from_attr(new_attr), Color::Blue as u8);
}

#[test]
fn test_set_bg() {
    let attr = make_color(Color::White, Color::Black);
    let new_attr = set_bg(attr, Color::Green);
    assert_eq!(fg_from_attr(new_attr), Color::White as u8);
    assert_eq!(bg_from_attr(new_attr), Color::Green as u8);
}

#[test]
fn test_vga_cell_new() {
    let cell = VgaCell::new(b'A', 0x07);
    assert_eq!({ cell.ascii }, b'A');
    assert_eq!({ cell.color }, 0x07);
}

#[test]
fn test_vga_cell_blank() {
    let cell = VgaCell::blank(0x1F);
    assert_eq!({ cell.ascii }, b' ');
    assert_eq!({ cell.color }, 0x1F);
}

#[test]
fn test_vga_cell_default() {
    let cell = VgaCell::default();
    assert_eq!({ cell.ascii }, b' ');
    assert_eq!({ cell.color }, 0x07);
}

#[test]
fn test_vga_cell_size() {
    assert_eq!(core::mem::size_of::<VgaCell>(), 2);
}

#[test]
fn test_vga_dimensions() {
    assert_eq!(VGA_WIDTH, 80);
    assert_eq!(VGA_HEIGHT, 25);
    assert_eq!(VGA_CELLS, 80 * 25);
    assert_eq!(VGA_BUFFER_SIZE, 80 * 25 * 2);
}

#[test]
fn test_vga_buffer_address() {
    assert_eq!(VGA_BUFFER_ADDR, 0xB8000);
}

#[test]
fn test_crtc_ports() {
    assert_eq!(VGA_CRTC_INDEX, 0x3D4);
    assert_eq!(VGA_CRTC_DATA, 0x3D5);
}

#[test]
fn test_default_colors() {
    assert_eq!(DEFAULT_FG, 0x07);
    assert_eq!(DEFAULT_BG, 0x00);
    assert_eq!(DEFAULT_COLOR, 0x07);
}

#[test]
fn test_ascii_constants() {
    assert_eq!(ASCII_ESC, 0x1B);
    assert_eq!(ASCII_NEWLINE, b'\n');
    assert_eq!(ASCII_CR, b'\r');
    assert_eq!(ASCII_SPACE, 0x20);
    assert_eq!(ASCII_TILDE, 0x7E);
    assert_eq!(ASCII_LBRACKET, b'[');
}

#[test]
fn test_log_level_values() {
    assert_eq!(LogLevel::Trace as u8, 0);
    assert_eq!(LogLevel::Debug as u8, 1);
    assert_eq!(LogLevel::Info as u8, 2);
    assert_eq!(LogLevel::Warning as u8, 3);
    assert_eq!(LogLevel::Error as u8, 4);
    assert_eq!(LogLevel::Critical as u8, 5);
}

#[test]
fn test_log_level_default() {
    assert_eq!(LogLevel::default(), LogLevel::Info);
}

#[test]
fn test_log_level_colors() {
    assert_eq!(LogLevel::Trace.color(), Color::DarkGrey);
    assert_eq!(LogLevel::Debug.color(), Color::LightGrey);
    assert_eq!(LogLevel::Info.color(), Color::White);
    assert_eq!(LogLevel::Warning.color(), Color::Yellow);
    assert_eq!(LogLevel::Error.color(), Color::LightRed);
    assert_eq!(LogLevel::Critical.color(), Color::Red);
}

#[test]
fn test_log_level_as_str() {
    assert_eq!(LogLevel::Trace.as_str(), "TRACE");
    assert_eq!(LogLevel::Debug.as_str(), "DEBUG");
    assert_eq!(LogLevel::Info.as_str(), "INFO");
    assert_eq!(LogLevel::Warning.as_str(), "WARN");
    assert_eq!(LogLevel::Error.as_str(), "ERROR");
    assert_eq!(LogLevel::Critical.as_str(), "CRIT");
}

#[test]
fn test_log_level_ordering() {
    assert!(LogLevel::Trace < LogLevel::Debug);
    assert!(LogLevel::Debug < LogLevel::Info);
    assert!(LogLevel::Info < LogLevel::Warning);
    assert!(LogLevel::Warning < LogLevel::Error);
    assert!(LogLevel::Error < LogLevel::Critical);
}

#[test]
fn test_parser_initial_state() {
    let parser = AnsiParser::new();
    assert_eq!(parser.state(), ParserState::Normal);
}

#[test]
fn test_parser_default() {
    let parser = AnsiParser::default();
    assert_eq!(parser.state(), ParserState::Normal);
}

#[test]
fn test_parser_reset() {
    let mut parser = AnsiParser::new();
    parser.process(0x1B);
    assert_eq!(parser.state(), ParserState::Escape);
    parser.reset();
    assert_eq!(parser.state(), ParserState::Normal);
}

#[test]
fn test_parser_normal_char() {
    let mut parser = AnsiParser::new();
    let action = parser.process(b'A');
    assert_eq!(action, Some(AnsiAction::Print(b'A')));
    assert_eq!(parser.state(), ParserState::Normal);
}

#[test]
fn test_parser_escape_sequence() {
    let mut parser = AnsiParser::new();
    let action = parser.process(0x1B);
    assert_eq!(action, None);
    assert_eq!(parser.state(), ParserState::Escape);
    let action = parser.process(b'[');
    assert_eq!(action, None);
    assert_eq!(parser.state(), ParserState::Csi);
}

#[test]
fn test_parser_unknown_escape() {
    let mut parser = AnsiParser::new();
    parser.process(0x1B);
    let action = parser.process(b'X');
    assert_eq!(action, Some(AnsiAction::Print(b'X')));
    assert_eq!(parser.state(), ParserState::Normal);
}

#[test]
fn test_parser_sgr_reset() {
    let mut parser = AnsiParser::new();
    parser.process(0x1B);
    parser.process(b'[');
    parser.process(b'0');
    let action = parser.process(b'm');
    assert_eq!(action, Some(AnsiAction::Sgr(0, None)));
    assert_eq!(parser.state(), ParserState::Normal);
}

#[test]
fn test_parser_sgr_implicit_zero() {
    let mut parser = AnsiParser::new();
    parser.process(0x1B);
    parser.process(b'[');
    let action = parser.process(b'm');
    assert_eq!(action, Some(AnsiAction::Sgr(0, None)));
}

#[test]
fn test_parser_sgr_foreground() {
    let mut parser = AnsiParser::new();
    parser.process(0x1B);
    parser.process(b'[');
    parser.process(b'3');
    parser.process(b'1');
    let action = parser.process(b'm');
    assert_eq!(action, Some(AnsiAction::Sgr(31, None)));
}

#[test]
fn test_parser_sgr_two_params() {
    let mut parser = AnsiParser::new();
    parser.process(0x1B);
    parser.process(b'[');
    parser.process(b'3');
    parser.process(b'1');
    parser.process(b';');
    parser.process(b'4');
    parser.process(b'4');
    let action = parser.process(b'm');
    assert_eq!(action, Some(AnsiAction::Sgr(31, Some(44))));
}

#[test]
fn test_parser_cursor_position() {
    let mut parser = AnsiParser::new();
    parser.process(0x1B);
    parser.process(b'[');
    parser.process(b'1');
    parser.process(b'0');
    parser.process(b';');
    parser.process(b'2');
    parser.process(b'0');
    let action = parser.process(b'H');
    assert_eq!(action, Some(AnsiAction::CursorPosition(9, 19)));
}

#[test]
fn test_parser_cursor_home() {
    let mut parser = AnsiParser::new();
    parser.process(0x1B);
    parser.process(b'[');
    let action = parser.process(b'H');
    assert_eq!(action, Some(AnsiAction::CursorPosition(0, 0)));
}

#[test]
fn test_parser_erase_display() {
    let mut parser = AnsiParser::new();
    parser.process(0x1B);
    parser.process(b'[');
    parser.process(b'2');
    let action = parser.process(b'J');
    assert_eq!(action, Some(AnsiAction::EraseDisplay(2)));
}

#[test]
fn test_parser_erase_line() {
    let mut parser = AnsiParser::new();
    parser.process(0x1B);
    parser.process(b'[');
    let action = parser.process(b'K');
    assert_eq!(action, Some(AnsiAction::EraseLine(0)));
}

#[test]
fn test_parser_cursor_up() {
    let mut parser = AnsiParser::new();
    parser.process(0x1B);
    parser.process(b'[');
    parser.process(b'5');
    let action = parser.process(b'A');
    assert_eq!(action, Some(AnsiAction::CursorUp(5)));
}

#[test]
fn test_parser_cursor_down() {
    let mut parser = AnsiParser::new();
    parser.process(0x1B);
    parser.process(b'[');
    parser.process(b'3');
    let action = parser.process(b'B');
    assert_eq!(action, Some(AnsiAction::CursorDown(3)));
}

#[test]
fn test_parser_cursor_forward() {
    let mut parser = AnsiParser::new();
    parser.process(0x1B);
    parser.process(b'[');
    parser.process(b'1');
    parser.process(b'0');
    let action = parser.process(b'C');
    assert_eq!(action, Some(AnsiAction::CursorForward(10)));
}

#[test]
fn test_parser_cursor_back() {
    let mut parser = AnsiParser::new();
    parser.process(0x1B);
    parser.process(b'[');
    let action = parser.process(b'D');
    assert_eq!(action, Some(AnsiAction::CursorBack(1)));
}

#[test]
fn test_parser_unknown_csi() {
    let mut parser = AnsiParser::new();
    parser.process(0x1B);
    parser.process(b'[');
    parser.process(b'?');
    assert_eq!(parser.state(), ParserState::Normal);
}

#[test]
fn test_apply_sgr_reset() {
    let current = make_color(Color::Red, Color::Blue);
    let result = apply_sgr(current, 0);
    assert_eq!(result, make_color(Color::LightGrey, Color::Black));
}

#[test]
fn test_apply_sgr_foreground() {
    let current = make_color(Color::LightGrey, Color::Black);
    let result = apply_sgr(current, 31);
    assert_eq!(fg_from_attr(result), Color::Red as u8);
    assert_eq!(bg_from_attr(result), Color::Black as u8);
}

#[test]
fn test_apply_sgr_background() {
    let current = make_color(Color::White, Color::Black);
    let result = apply_sgr(current, 44);
    assert_eq!(fg_from_attr(result), Color::White as u8);
    assert_eq!(bg_from_attr(result), Color::Blue as u8);
}

#[test]
fn test_apply_sgr_bright_foreground() {
    let current = make_color(Color::LightGrey, Color::Black);
    let result = apply_sgr(current, 91);
    assert_eq!(fg_from_attr(result), Color::LightRed as u8);
}

#[test]
fn test_apply_sgr_bright_background() {
    let current = make_color(Color::White, Color::Black);
    let result = apply_sgr(current, 104);
    assert_eq!(bg_from_attr(result), Color::LightBlue as u8);
}

#[test]
fn test_apply_sgr_bold() {
    let current = make_color(Color::Blue, Color::Black);
    let result = apply_sgr(current, 1);
    assert_eq!(fg_from_attr(result), 0x09);
}

#[test]
fn test_apply_sgr_unsupported() {
    let current = make_color(Color::White, Color::Black);
    let result = apply_sgr(current, 99);
    assert_eq!(result, current);
}

#[test]
fn test_console_stats_new() {
    let stats = ConsoleStats::new();
    assert_eq!(stats.messages_written.load(core::sync::atomic::Ordering::Relaxed), 0);
    assert_eq!(stats.bytes_written.load(core::sync::atomic::Ordering::Relaxed), 0);
    assert_eq!(stats.errors.load(core::sync::atomic::Ordering::Relaxed), 0);
    assert_eq!(stats.uptime_ticks.load(core::sync::atomic::Ordering::Relaxed), 0);
}

#[test]
fn test_console_stats_default() {
    let stats = ConsoleStats::default();
    assert_eq!(stats.messages_written.load(core::sync::atomic::Ordering::Relaxed), 0);
}

#[test]
fn test_console_stats_inc_messages() {
    let stats = ConsoleStats::new();
    stats.inc_messages();
    stats.inc_messages();
    assert_eq!(stats.messages_written.load(core::sync::atomic::Ordering::Relaxed), 2);
}

#[test]
fn test_console_stats_add_bytes() {
    let stats = ConsoleStats::new();
    stats.add_bytes(100);
    stats.add_bytes(50);
    assert_eq!(stats.bytes_written.load(core::sync::atomic::Ordering::Relaxed), 150);
}

#[test]
fn test_console_stats_inc_errors() {
    let stats = ConsoleStats::new();
    stats.inc_errors();
    assert_eq!(stats.errors.load(core::sync::atomic::Ordering::Relaxed), 1);
}

#[test]
fn test_console_stats_snapshot() {
    let stats = ConsoleStats::new();
    stats.inc_messages();
    stats.add_bytes(42);
    stats.inc_errors();
    let snapshot = stats.snapshot();
    assert_eq!(snapshot.messages_written, 1);
    assert_eq!(snapshot.bytes_written, 42);
    assert_eq!(snapshot.errors, 1);
}

#[test]
fn test_ansi_action_equality() {
    assert_eq!(AnsiAction::Print(b'A'), AnsiAction::Print(b'A'));
    assert_ne!(AnsiAction::Print(b'A'), AnsiAction::Print(b'B'));
    assert_eq!(AnsiAction::Sgr(31, None), AnsiAction::Sgr(31, None));
    assert_eq!(AnsiAction::Sgr(31, Some(44)), AnsiAction::Sgr(31, Some(44)));
    assert_ne!(AnsiAction::Sgr(31, None), AnsiAction::Sgr(32, None));
    assert_eq!(AnsiAction::CursorPosition(5, 10), AnsiAction::CursorPosition(5, 10));
    assert_ne!(AnsiAction::CursorPosition(5, 10), AnsiAction::CursorPosition(5, 11));
}

#[test]
fn test_parser_state_equality() {
    assert_eq!(ParserState::Normal, ParserState::Normal);
    assert_eq!(ParserState::Escape, ParserState::Escape);
    assert_eq!(ParserState::Csi, ParserState::Csi);
    assert_ne!(ParserState::Normal, ParserState::Escape);
}

#[test]
fn test_parser_state_default() {
    assert_eq!(ParserState::default(), ParserState::Normal);
}

#[test]
fn test_vga_buffer_bounds() {
    assert!(VGA_WIDTH <= 256);
    assert!(VGA_HEIGHT <= 256);
    assert!(VGA_CELLS <= u16::MAX as usize);
    assert!(VGA_BUFFER_SIZE <= u16::MAX as usize);
}

#[test]
fn test_cursor_position_bounds() {
    let max_pos = (VGA_HEIGHT - 1) * VGA_WIDTH + (VGA_WIDTH - 1);
    assert!(max_pos < u16::MAX as usize);
}

#[test]
fn test_vga_buffer_size_matches_cells() {
    assert_eq!(VGA_BUFFER_SIZE, VGA_CELLS * core::mem::size_of::<VgaCell>());
}

#[test]
fn test_color_from_ansi_bright() {
    assert_eq!(Color::from_ansi_bright(0), Color::DarkGrey);
    assert_eq!(Color::from_ansi_bright(1), Color::LightRed);
    assert_eq!(Color::from_ansi_bright(2), Color::LightGreen);
    assert_eq!(Color::from_ansi_bright(3), Color::Yellow);
    assert_eq!(Color::from_ansi_bright(4), Color::LightBlue);
    assert_eq!(Color::from_ansi_bright(5), Color::Pink);
    assert_eq!(Color::from_ansi_bright(6), Color::LightCyan);
    assert_eq!(Color::from_ansi_bright(7), Color::White);
}

#[test]
fn test_color_from_u8() {
    assert_eq!(Color::from_u8(0x0), Color::Black);
    assert_eq!(Color::from_u8(0x1), Color::Blue);
    assert_eq!(Color::from_u8(0xF), Color::White);
    assert_eq!(Color::from_u8(0xFF), Color::LightGrey);
}

#[test]
fn test_color_as_u8() {
    assert_eq!(Color::Black.as_u8(), 0x0);
    assert_eq!(Color::White.as_u8(), 0xF);
}

#[test]
fn test_color_bright() {
    assert_eq!(Color::Black.bright(), Color::DarkGrey);
    assert_eq!(Color::Blue.bright(), Color::LightBlue);
    assert_eq!(Color::Brown.bright(), Color::Yellow);
    assert_eq!(Color::White.bright(), Color::White);
}

#[test]
fn test_color_dim() {
    assert_eq!(Color::DarkGrey.dim(), Color::Black);
    assert_eq!(Color::LightBlue.dim(), Color::Blue);
    assert_eq!(Color::Yellow.dim(), Color::Brown);
    assert_eq!(Color::Black.dim(), Color::Black);
}

#[test]
fn test_color_is_bright() {
    assert!(!Color::Black.is_bright());
    assert!(!Color::Blue.is_bright());
    assert!(Color::DarkGrey.is_bright());
    assert!(Color::White.is_bright());
}

#[test]
fn test_color_name() {
    assert_eq!(Color::Black.name(), "Black");
    assert_eq!(Color::White.name(), "White");
    assert_eq!(Color::LightGrey.name(), "LightGrey");
}

#[test]
fn test_vga_cell_with_colors() {
    let cell = VgaCell::with_colors(b'X', Color::White, Color::Blue);
    assert_eq!({ cell.ascii }, b'X');
    assert_eq!(cell.fg(), Color::White);
    assert_eq!(cell.bg(), Color::Blue);
}

#[test]
fn test_vga_cell_is_blank() {
    let blank = VgaCell::blank(0x07);
    let non_blank = VgaCell::new(b'A', 0x07);
    assert!(blank.is_blank());
    assert!(!non_blank.is_blank());
}

#[test]
fn test_vga_cell_as_u16() {
    let cell = VgaCell::new(b'A', 0x1F);
    assert_eq!(cell.as_u16(), 0x1F41);
}

#[test]
fn test_vga_cell_from_u16() {
    let cell = VgaCell::from_u16(0x1F41);
    assert_eq!({ cell.ascii }, b'A');
    assert_eq!({ cell.color }, 0x1F);
}

#[test]
fn test_next_tab_stop() {
    assert_eq!(next_tab_stop(0), 8);
    assert_eq!(next_tab_stop(1), 8);
    assert_eq!(next_tab_stop(7), 8);
    assert_eq!(next_tab_stop(8), 16);
    assert_eq!(next_tab_stop(15), 16);
    assert_eq!(next_tab_stop(16), 24);
}

#[test]
fn test_is_valid_row() {
    assert!(is_valid_row(0));
    assert!(is_valid_row(24));
    assert!(!is_valid_row(25));
    assert!(!is_valid_row(100));
}

#[test]
fn test_is_valid_col() {
    assert!(is_valid_col(0));
    assert!(is_valid_col(79));
    assert!(!is_valid_col(80));
    assert!(!is_valid_col(100));
}

#[test]
fn test_is_valid_position() {
    assert!(is_valid_position(0, 0));
    assert!(is_valid_position(24, 79));
    assert!(!is_valid_position(25, 0));
    assert!(!is_valid_position(0, 80));
    assert!(!is_valid_position(25, 80));
}

#[test]
fn test_position_to_offset() {
    assert_eq!(position_to_offset(0, 0), 0);
    assert_eq!(position_to_offset(0, 1), 1);
    assert_eq!(position_to_offset(1, 0), 80);
    assert_eq!(position_to_offset(1, 1), 81);
    assert_eq!(position_to_offset(24, 79), 1999);
}

#[test]
fn test_offset_to_position() {
    assert_eq!(offset_to_position(0), (0, 0));
    assert_eq!(offset_to_position(1), (0, 1));
    assert_eq!(offset_to_position(80), (1, 0));
    assert_eq!(offset_to_position(81), (1, 1));
    assert_eq!(offset_to_position(1999), (24, 79));
}

#[test]
fn test_is_printable() {
    assert!(!is_printable(0x00));
    assert!(!is_printable(0x1F));
    assert!(is_printable(0x20));
    assert!(is_printable(b'A'));
    assert!(is_printable(0x7E));
    assert!(!is_printable(0x7F));
}

#[test]
fn test_is_control() {
    assert!(is_control(0x00));
    assert!(is_control(0x1F));
    assert!(!is_control(0x20));
    assert!(!is_control(b'A'));
    assert!(!is_control(0x7E));
    assert!(is_control(0x7F));
}

#[test]
fn test_parser_save_cursor() {
    let mut parser = AnsiParser::new();
    parser.process(0x1B);
    parser.process(b'[');
    let action = parser.process(b's');
    assert_eq!(action, Some(AnsiAction::SaveCursor));
}

#[test]
fn test_parser_restore_cursor() {
    let mut parser = AnsiParser::new();
    parser.process(0x1B);
    parser.process(b'[');
    let action = parser.process(b'u');
    assert_eq!(action, Some(AnsiAction::RestoreCursor));
}

#[test]
fn test_parser_show_cursor() {
    let mut parser = AnsiParser::new();
    parser.process(0x1B);
    parser.process(b'[');
    parser.process(b'?');
    parser.process(b'2');
    parser.process(b'5');
    let action = parser.process(b'h');
    assert_eq!(action, Some(AnsiAction::ShowCursor));
}

#[test]
fn test_parser_hide_cursor() {
    let mut parser = AnsiParser::new();
    parser.process(0x1B);
    parser.process(b'[');
    parser.process(b'?');
    parser.process(b'2');
    parser.process(b'5');
    let action = parser.process(b'l');
    assert_eq!(action, Some(AnsiAction::HideCursor));
}

#[test]
fn test_parser_dec_private_mode_unknown() {
    let mut parser = AnsiParser::new();
    parser.process(0x1B);
    parser.process(b'[');
    parser.process(b'?');
    parser.process(b'7');
    let action = parser.process(b'h');
    assert_eq!(action, None);
}

#[test]
fn test_parser_dec_private_state() {
    let mut parser = AnsiParser::new();
    parser.process(0x1B);
    parser.process(b'[');
    parser.process(b'?');
    assert_eq!(parser.state(), ParserState::DecPrivate);
    parser.process(b'2');
    parser.process(b'5');
    parser.process(b'h');
    assert_eq!(parser.state(), ParserState::Normal);
}

#[test]
fn test_ansi_action_is_cursor_action() {
    assert!(AnsiAction::CursorPosition(0, 0).is_cursor_action());
    assert!(AnsiAction::CursorUp(1).is_cursor_action());
    assert!(AnsiAction::SaveCursor.is_cursor_action());
    assert!(AnsiAction::RestoreCursor.is_cursor_action());
    assert!(!AnsiAction::Sgr(0, None).is_cursor_action());
    assert!(!AnsiAction::Print(b'A').is_cursor_action());
}

#[test]
fn test_ansi_action_is_sgr_action() {
    assert!(AnsiAction::Sgr(0, None).is_sgr_action());
    assert!(AnsiAction::Sgr(31, Some(44)).is_sgr_action());
    assert!(!AnsiAction::Print(b'A').is_sgr_action());
    assert!(!AnsiAction::CursorUp(1).is_sgr_action());
}

#[test]
fn test_ansi_action_is_erase_action() {
    assert!(AnsiAction::EraseDisplay(2).is_erase_action());
    assert!(AnsiAction::EraseLine(0).is_erase_action());
    assert!(!AnsiAction::Print(b'A').is_erase_action());
    assert!(!AnsiAction::CursorUp(1).is_erase_action());
}

#[test]
fn test_additional_ascii_constants() {
    assert_eq!(ASCII_TAB, b'\t');
    assert_eq!(ASCII_BACKSPACE, 0x08);
    assert_eq!(ASCII_BELL, 0x07);
    assert_eq!(ASCII_FORM_FEED, 0x0C);
    assert_eq!(ASCII_DELETE, 0x7F);
}

#[test]
fn test_tab_width() {
    assert_eq!(TAB_WIDTH, 8);
}

#[test]
fn test_color_constants() {
    assert_eq!(ERROR_COLOR, 0x0C);
    assert_eq!(WARNING_COLOR, 0x0E);
    assert_eq!(SUCCESS_COLOR, 0x0A);
    assert_eq!(INFO_COLOR, 0x0B);
    assert_eq!(HIGHLIGHT_COLOR, 0x1F);
    assert_eq!(DIM_COLOR, 0x08);
}
