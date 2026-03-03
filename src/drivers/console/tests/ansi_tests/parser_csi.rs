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

use crate::drivers::console::ansi::*;
use crate::drivers::console::types::*;

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
fn test_parser_unknown_csi() {
    let mut parser = AnsiParser::new();
    parser.process(0x1B);
    parser.process(b'[');
    parser.process(b'?');
    assert_eq!(parser.state(), ParserState::DecPrivate);
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
