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
