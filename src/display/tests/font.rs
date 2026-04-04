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

use crate::display::font::get_glyph;

#[test]
fn test_get_glyph_space() {
    let glyph = get_glyph(' ');
    assert_eq!(glyph.len(), 16);
    for byte in glyph.iter() {
        assert_eq!(*byte, 0);
    }
}

#[test]
fn test_get_glyph_exclamation() {
    let glyph = get_glyph('!');
    assert_eq!(glyph.len(), 16);
    let has_content = glyph.iter().any(|&b| b != 0);
    assert!(has_content);
}

#[test]
fn test_get_glyph_digit_zero() {
    let glyph = get_glyph('0');
    assert_eq!(glyph.len(), 16);
    let has_content = glyph.iter().any(|&b| b != 0);
    assert!(has_content);
}

#[test]
fn test_get_glyph_digit_nine() {
    let glyph = get_glyph('9');
    assert_eq!(glyph.len(), 16);
    let has_content = glyph.iter().any(|&b| b != 0);
    assert!(has_content);
}

#[test]
fn test_get_glyph_uppercase_a() {
    let glyph = get_glyph('A');
    assert_eq!(glyph.len(), 16);
    let has_content = glyph.iter().any(|&b| b != 0);
    assert!(has_content);
}

#[test]
fn test_get_glyph_uppercase_z() {
    let glyph = get_glyph('Z');
    assert_eq!(glyph.len(), 16);
    let has_content = glyph.iter().any(|&b| b != 0);
    assert!(has_content);
}

#[test]
fn test_get_glyph_lowercase_a() {
    let glyph = get_glyph('a');
    assert_eq!(glyph.len(), 16);
    let has_content = glyph.iter().any(|&b| b != 0);
    assert!(has_content);
}

#[test]
fn test_get_glyph_lowercase_z() {
    let glyph = get_glyph('z');
    assert_eq!(glyph.len(), 16);
    let has_content = glyph.iter().any(|&b| b != 0);
    assert!(has_content);
}

#[test]
fn test_get_glyph_at_symbol() {
    let glyph = get_glyph('@');
    assert_eq!(glyph.len(), 16);
    let has_content = glyph.iter().any(|&b| b != 0);
    assert!(has_content);
}

#[test]
fn test_get_glyph_hash() {
    let glyph = get_glyph('#');
    assert_eq!(glyph.len(), 16);
    let has_content = glyph.iter().any(|&b| b != 0);
    assert!(has_content);
}

#[test]
fn test_get_glyph_dollar() {
    let glyph = get_glyph('$');
    assert_eq!(glyph.len(), 16);
    let has_content = glyph.iter().any(|&b| b != 0);
    assert!(has_content);
}

#[test]
fn test_get_glyph_percent() {
    let glyph = get_glyph('%');
    assert_eq!(glyph.len(), 16);
    let has_content = glyph.iter().any(|&b| b != 0);
    assert!(has_content);
}

#[test]
fn test_get_glyph_asterisk() {
    let glyph = get_glyph('*');
    assert_eq!(glyph.len(), 16);
    let has_content = glyph.iter().any(|&b| b != 0);
    assert!(has_content);
}

#[test]
fn test_get_glyph_plus() {
    let glyph = get_glyph('+');
    assert_eq!(glyph.len(), 16);
    let has_content = glyph.iter().any(|&b| b != 0);
    assert!(has_content);
}

#[test]
fn test_get_glyph_minus() {
    let glyph = get_glyph('-');
    assert_eq!(glyph.len(), 16);
    let has_content = glyph.iter().any(|&b| b != 0);
    assert!(has_content);
}

#[test]
fn test_get_glyph_period() {
    let glyph = get_glyph('.');
    assert_eq!(glyph.len(), 16);
    let has_content = glyph.iter().any(|&b| b != 0);
    assert!(has_content);
}

#[test]
fn test_get_glyph_slash() {
    let glyph = get_glyph('/');
    assert_eq!(glyph.len(), 16);
    let has_content = glyph.iter().any(|&b| b != 0);
    assert!(has_content);
}

#[test]
fn test_get_glyph_colon() {
    let glyph = get_glyph(':');
    assert_eq!(glyph.len(), 16);
    let has_content = glyph.iter().any(|&b| b != 0);
    assert!(has_content);
}

#[test]
fn test_get_glyph_semicolon() {
    let glyph = get_glyph(';');
    assert_eq!(glyph.len(), 16);
    let has_content = glyph.iter().any(|&b| b != 0);
    assert!(has_content);
}

#[test]
fn test_get_glyph_less_than() {
    let glyph = get_glyph('<');
    assert_eq!(glyph.len(), 16);
    let has_content = glyph.iter().any(|&b| b != 0);
    assert!(has_content);
}

#[test]
fn test_get_glyph_equals() {
    let glyph = get_glyph('=');
    assert_eq!(glyph.len(), 16);
    let has_content = glyph.iter().any(|&b| b != 0);
    assert!(has_content);
}

#[test]
fn test_get_glyph_greater_than() {
    let glyph = get_glyph('>');
    assert_eq!(glyph.len(), 16);
    let has_content = glyph.iter().any(|&b| b != 0);
    assert!(has_content);
}

#[test]
fn test_get_glyph_question() {
    let glyph = get_glyph('?');
    assert_eq!(glyph.len(), 16);
    let has_content = glyph.iter().any(|&b| b != 0);
    assert!(has_content);
}

#[test]
fn test_get_glyph_open_bracket() {
    let glyph = get_glyph('[');
    assert_eq!(glyph.len(), 16);
    let has_content = glyph.iter().any(|&b| b != 0);
    assert!(has_content);
}

#[test]
fn test_get_glyph_close_bracket() {
    let glyph = get_glyph(']');
    assert_eq!(glyph.len(), 16);
    let has_content = glyph.iter().any(|&b| b != 0);
    assert!(has_content);
}

#[test]
fn test_get_glyph_backslash() {
    let glyph = get_glyph('\\');
    assert_eq!(glyph.len(), 16);
    let has_content = glyph.iter().any(|&b| b != 0);
    assert!(has_content);
}

#[test]
fn test_get_glyph_caret() {
    let glyph = get_glyph('^');
    assert_eq!(glyph.len(), 16);
    let has_content = glyph.iter().any(|&b| b != 0);
    assert!(has_content);
}

#[test]
fn test_get_glyph_underscore() {
    let glyph = get_glyph('_');
    assert_eq!(glyph.len(), 16);
    let has_content = glyph.iter().any(|&b| b != 0);
    assert!(has_content);
}

#[test]
fn test_get_glyph_backtick() {
    let glyph = get_glyph('`');
    assert_eq!(glyph.len(), 16);
    let has_content = glyph.iter().any(|&b| b != 0);
    assert!(has_content);
}

#[test]
fn test_get_glyph_open_brace() {
    let glyph = get_glyph('{');
    assert_eq!(glyph.len(), 16);
    let has_content = glyph.iter().any(|&b| b != 0);
    assert!(has_content);
}

#[test]
fn test_get_glyph_close_brace() {
    let glyph = get_glyph('}');
    assert_eq!(glyph.len(), 16);
    let has_content = glyph.iter().any(|&b| b != 0);
    assert!(has_content);
}

#[test]
fn test_get_glyph_pipe() {
    let glyph = get_glyph('|');
    assert_eq!(glyph.len(), 16);
    let has_content = glyph.iter().any(|&b| b != 0);
    assert!(has_content);
}

#[test]
fn test_get_glyph_tilde() {
    let glyph = get_glyph('~');
    assert_eq!(glyph.len(), 16);
    let has_content = glyph.iter().any(|&b| b != 0);
    assert!(has_content);
}

#[test]
fn test_get_glyph_unknown_returns_empty() {
    let glyph = get_glyph('\x00');
    assert_eq!(glyph.len(), 16);
    for byte in glyph.iter() {
        assert_eq!(*byte, 0);
    }
}

#[test]
fn test_get_glyph_high_ascii_returns_empty() {
    let glyph = get_glyph('\x7F');
    assert_eq!(glyph.len(), 16);
    for byte in glyph.iter() {
        assert_eq!(*byte, 0);
    }
}

#[test]
fn test_get_glyph_control_char_returns_empty() {
    let glyph = get_glyph('\x01');
    assert_eq!(glyph.len(), 16);
    for byte in glyph.iter() {
        assert_eq!(*byte, 0);
    }
}

#[test]
fn test_get_glyph_all_digits_different() {
    let glyphs: alloc::vec::Vec<[u8; 16]> = ('0'..='9').map(|c| get_glyph(c)).collect();
    for i in 0..glyphs.len() {
        for j in (i + 1)..glyphs.len() {
            assert_ne!(glyphs[i], glyphs[j]);
        }
    }
}

#[test]
fn test_get_glyph_all_uppercase_different() {
    let glyphs: alloc::vec::Vec<[u8; 16]> = ('A'..='Z').map(|c| get_glyph(c)).collect();
    for i in 0..glyphs.len() {
        for j in (i + 1)..glyphs.len() {
            assert_ne!(glyphs[i], glyphs[j]);
        }
    }
}

#[test]
fn test_get_glyph_all_lowercase_different() {
    let glyphs: alloc::vec::Vec<[u8; 16]> = ('a'..='z').map(|c| get_glyph(c)).collect();
    for i in 0..glyphs.len() {
        for j in (i + 1)..glyphs.len() {
            assert_ne!(glyphs[i], glyphs[j]);
        }
    }
}

#[test]
fn test_get_glyph_uppercase_lowercase_different() {
    for c in 'a'..='z' {
        let lower = get_glyph(c);
        let upper = get_glyph(c.to_ascii_uppercase());
        assert_ne!(lower, upper);
    }
}

#[test]
fn test_glyph_size_is_16_bytes() {
    let glyph = get_glyph('X');
    assert_eq!(core::mem::size_of_val(&glyph), 16);
}

#[test]
fn test_get_glyph_printable_range_0x20_to_0x2f() {
    for code in 0x20u8..=0x2F {
        let c = code as char;
        let glyph = get_glyph(c);
        assert_eq!(glyph.len(), 16);
    }
}

#[test]
fn test_get_glyph_printable_range_0x30_to_0x3f() {
    for code in 0x30u8..=0x3F {
        let c = code as char;
        let glyph = get_glyph(c);
        assert_eq!(glyph.len(), 16);
    }
}

#[test]
fn test_get_glyph_printable_range_0x40_to_0x4f() {
    for code in 0x40u8..=0x4F {
        let c = code as char;
        let glyph = get_glyph(c);
        assert_eq!(glyph.len(), 16);
    }
}

#[test]
fn test_get_glyph_printable_range_0x50_to_0x5f() {
    for code in 0x50u8..=0x5F {
        let c = code as char;
        let glyph = get_glyph(c);
        assert_eq!(glyph.len(), 16);
    }
}

#[test]
fn test_get_glyph_printable_range_0x60_to_0x6f() {
    for code in 0x60u8..=0x6F {
        let c = code as char;
        let glyph = get_glyph(c);
        assert_eq!(glyph.len(), 16);
    }
}

#[test]
fn test_get_glyph_printable_range_0x70_to_0x7e() {
    for code in 0x70u8..=0x7E {
        let c = code as char;
        let glyph = get_glyph(c);
        assert_eq!(glyph.len(), 16);
    }
}

#[test]
fn test_get_glyph_open_paren() {
    let glyph = get_glyph('(');
    assert_eq!(glyph.len(), 16);
    let has_content = glyph.iter().any(|&b| b != 0);
    assert!(has_content);
}

#[test]
fn test_get_glyph_close_paren() {
    let glyph = get_glyph(')');
    assert_eq!(glyph.len(), 16);
    let has_content = glyph.iter().any(|&b| b != 0);
    assert!(has_content);
}

#[test]
fn test_get_glyph_comma() {
    let glyph = get_glyph(',');
    assert_eq!(glyph.len(), 16);
    let has_content = glyph.iter().any(|&b| b != 0);
    assert!(has_content);
}

#[test]
fn test_get_glyph_double_quote() {
    let glyph = get_glyph('"');
    assert_eq!(glyph.len(), 16);
    let has_content = glyph.iter().any(|&b| b != 0);
    assert!(has_content);
}

#[test]
fn test_get_glyph_single_quote() {
    let glyph = get_glyph('\'');
    assert_eq!(glyph.len(), 16);
    let has_content = glyph.iter().any(|&b| b != 0);
    assert!(has_content);
}

#[test]
fn test_get_glyph_ampersand() {
    let glyph = get_glyph('&');
    assert_eq!(glyph.len(), 16);
    let has_content = glyph.iter().any(|&b| b != 0);
    assert!(has_content);
}

#[test]
fn test_glyph_consistent_retrieval() {
    let glyph1 = get_glyph('M');
    let glyph2 = get_glyph('M');
    assert_eq!(glyph1, glyph2);
}

#[test]
fn test_all_printable_ascii_have_glyphs() {
    for code in 0x21u8..=0x7E {
        let c = code as char;
        let glyph = get_glyph(c);
        let has_content = glyph.iter().any(|&b| b != 0);
        assert!(has_content);
    }
}
