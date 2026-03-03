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
