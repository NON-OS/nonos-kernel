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
use crate::test::framework::TestResult;

pub(crate) fn test_get_glyph_space() -> TestResult {
    let glyph = get_glyph(' ');
    if glyph.len() != 16 {
        return TestResult::Fail;
    }
    for byte in glyph.iter() {
        if *byte != 0 {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_exclamation() -> TestResult {
    let glyph = get_glyph('!');
    if glyph.len() != 16 {
        return TestResult::Fail;
    }
    let has_content = glyph.iter().any(|&b| b != 0);
    if !has_content {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_digit_zero() -> TestResult {
    let glyph = get_glyph('0');
    if glyph.len() != 16 {
        return TestResult::Fail;
    }
    let has_content = glyph.iter().any(|&b| b != 0);
    if !has_content {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_digit_nine() -> TestResult {
    let glyph = get_glyph('9');
    if glyph.len() != 16 {
        return TestResult::Fail;
    }
    let has_content = glyph.iter().any(|&b| b != 0);
    if !has_content {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_uppercase_a() -> TestResult {
    let glyph = get_glyph('A');
    if glyph.len() != 16 {
        return TestResult::Fail;
    }
    let has_content = glyph.iter().any(|&b| b != 0);
    if !has_content {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_uppercase_z() -> TestResult {
    let glyph = get_glyph('Z');
    if glyph.len() != 16 {
        return TestResult::Fail;
    }
    let has_content = glyph.iter().any(|&b| b != 0);
    if !has_content {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_lowercase_a() -> TestResult {
    let glyph = get_glyph('a');
    if glyph.len() != 16 {
        return TestResult::Fail;
    }
    let has_content = glyph.iter().any(|&b| b != 0);
    if !has_content {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_lowercase_z() -> TestResult {
    let glyph = get_glyph('z');
    if glyph.len() != 16 {
        return TestResult::Fail;
    }
    let has_content = glyph.iter().any(|&b| b != 0);
    if !has_content {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_at_symbol() -> TestResult {
    let glyph = get_glyph('@');
    if glyph.len() != 16 {
        return TestResult::Fail;
    }
    let has_content = glyph.iter().any(|&b| b != 0);
    if !has_content {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_hash() -> TestResult {
    let glyph = get_glyph('#');
    if glyph.len() != 16 {
        return TestResult::Fail;
    }
    let has_content = glyph.iter().any(|&b| b != 0);
    if !has_content {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_dollar() -> TestResult {
    let glyph = get_glyph('$');
    if glyph.len() != 16 {
        return TestResult::Fail;
    }
    let has_content = glyph.iter().any(|&b| b != 0);
    if !has_content {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_percent() -> TestResult {
    let glyph = get_glyph('%');
    if glyph.len() != 16 {
        return TestResult::Fail;
    }
    let has_content = glyph.iter().any(|&b| b != 0);
    if !has_content {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_asterisk() -> TestResult {
    let glyph = get_glyph('*');
    if glyph.len() != 16 {
        return TestResult::Fail;
    }
    let has_content = glyph.iter().any(|&b| b != 0);
    if !has_content {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_plus() -> TestResult {
    let glyph = get_glyph('+');
    if glyph.len() != 16 {
        return TestResult::Fail;
    }
    let has_content = glyph.iter().any(|&b| b != 0);
    if !has_content {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_minus() -> TestResult {
    let glyph = get_glyph('-');
    if glyph.len() != 16 {
        return TestResult::Fail;
    }
    let has_content = glyph.iter().any(|&b| b != 0);
    if !has_content {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_period() -> TestResult {
    let glyph = get_glyph('.');
    if glyph.len() != 16 {
        return TestResult::Fail;
    }
    let has_content = glyph.iter().any(|&b| b != 0);
    if !has_content {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_slash() -> TestResult {
    let glyph = get_glyph('/');
    if glyph.len() != 16 {
        return TestResult::Fail;
    }
    let has_content = glyph.iter().any(|&b| b != 0);
    if !has_content {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_colon() -> TestResult {
    let glyph = get_glyph(':');
    if glyph.len() != 16 {
        return TestResult::Fail;
    }
    let has_content = glyph.iter().any(|&b| b != 0);
    if !has_content {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_semicolon() -> TestResult {
    let glyph = get_glyph(';');
    if glyph.len() != 16 {
        return TestResult::Fail;
    }
    let has_content = glyph.iter().any(|&b| b != 0);
    if !has_content {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_less_than() -> TestResult {
    let glyph = get_glyph('<');
    if glyph.len() != 16 {
        return TestResult::Fail;
    }
    let has_content = glyph.iter().any(|&b| b != 0);
    if !has_content {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_equals() -> TestResult {
    let glyph = get_glyph('=');
    if glyph.len() != 16 {
        return TestResult::Fail;
    }
    let has_content = glyph.iter().any(|&b| b != 0);
    if !has_content {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_greater_than() -> TestResult {
    let glyph = get_glyph('>');
    if glyph.len() != 16 {
        return TestResult::Fail;
    }
    let has_content = glyph.iter().any(|&b| b != 0);
    if !has_content {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_question() -> TestResult {
    let glyph = get_glyph('?');
    if glyph.len() != 16 {
        return TestResult::Fail;
    }
    let has_content = glyph.iter().any(|&b| b != 0);
    if !has_content {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_open_bracket() -> TestResult {
    let glyph = get_glyph('[');
    if glyph.len() != 16 {
        return TestResult::Fail;
    }
    let has_content = glyph.iter().any(|&b| b != 0);
    if !has_content {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_close_bracket() -> TestResult {
    let glyph = get_glyph(']');
    if glyph.len() != 16 {
        return TestResult::Fail;
    }
    let has_content = glyph.iter().any(|&b| b != 0);
    if !has_content {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_backslash() -> TestResult {
    let glyph = get_glyph('\\');
    if glyph.len() != 16 {
        return TestResult::Fail;
    }
    let has_content = glyph.iter().any(|&b| b != 0);
    if !has_content {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_caret() -> TestResult {
    let glyph = get_glyph('^');
    if glyph.len() != 16 {
        return TestResult::Fail;
    }
    let has_content = glyph.iter().any(|&b| b != 0);
    if !has_content {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_underscore() -> TestResult {
    let glyph = get_glyph('_');
    if glyph.len() != 16 {
        return TestResult::Fail;
    }
    let has_content = glyph.iter().any(|&b| b != 0);
    if !has_content {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_backtick() -> TestResult {
    let glyph = get_glyph('`');
    if glyph.len() != 16 {
        return TestResult::Fail;
    }
    let has_content = glyph.iter().any(|&b| b != 0);
    if !has_content {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_open_brace() -> TestResult {
    let glyph = get_glyph('{');
    if glyph.len() != 16 {
        return TestResult::Fail;
    }
    let has_content = glyph.iter().any(|&b| b != 0);
    if !has_content {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_close_brace() -> TestResult {
    let glyph = get_glyph('}');
    if glyph.len() != 16 {
        return TestResult::Fail;
    }
    let has_content = glyph.iter().any(|&b| b != 0);
    if !has_content {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_pipe() -> TestResult {
    let glyph = get_glyph('|');
    if glyph.len() != 16 {
        return TestResult::Fail;
    }
    let has_content = glyph.iter().any(|&b| b != 0);
    if !has_content {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_tilde() -> TestResult {
    let glyph = get_glyph('~');
    if glyph.len() != 16 {
        return TestResult::Fail;
    }
    let has_content = glyph.iter().any(|&b| b != 0);
    if !has_content {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_unknown_returns_empty() -> TestResult {
    let glyph = get_glyph('\x00');
    if glyph.len() != 16 {
        return TestResult::Fail;
    }
    for byte in glyph.iter() {
        if *byte != 0 {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_high_ascii_returns_empty() -> TestResult {
    let glyph = get_glyph('\x7F');
    if glyph.len() != 16 {
        return TestResult::Fail;
    }
    for byte in glyph.iter() {
        if *byte != 0 {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_control_char_returns_empty() -> TestResult {
    let glyph = get_glyph('\x01');
    if glyph.len() != 16 {
        return TestResult::Fail;
    }
    for byte in glyph.iter() {
        if *byte != 0 {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_all_digits_different() -> TestResult {
    let glyphs: alloc::vec::Vec<[u8; 16]> = ('0'..='9').map(|c| get_glyph(c)).collect();
    for i in 0..glyphs.len() {
        for j in (i + 1)..glyphs.len() {
            if glyphs[i] == glyphs[j] {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_all_uppercase_different() -> TestResult {
    let glyphs: alloc::vec::Vec<[u8; 16]> = ('A'..='Z').map(|c| get_glyph(c)).collect();
    for i in 0..glyphs.len() {
        for j in (i + 1)..glyphs.len() {
            if glyphs[i] == glyphs[j] {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_all_lowercase_different() -> TestResult {
    let glyphs: alloc::vec::Vec<[u8; 16]> = ('a'..='z').map(|c| get_glyph(c)).collect();
    for i in 0..glyphs.len() {
        for j in (i + 1)..glyphs.len() {
            if glyphs[i] == glyphs[j] {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_uppercase_lowercase_different() -> TestResult {
    for c in 'a'..='z' {
        let lower = get_glyph(c);
        let upper = get_glyph(c.to_ascii_uppercase());
        if lower == upper {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_glyph_size_is_16_bytes() -> TestResult {
    let glyph = get_glyph('X');
    if core::mem::size_of_val(&glyph) != 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_printable_range_0x20_to_0x2f() -> TestResult {
    for code in 0x20u8..=0x2F {
        let c = code as char;
        let glyph = get_glyph(c);
        if glyph.len() != 16 {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_printable_range_0x30_to_0x3f() -> TestResult {
    for code in 0x30u8..=0x3F {
        let c = code as char;
        let glyph = get_glyph(c);
        if glyph.len() != 16 {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_printable_range_0x40_to_0x4f() -> TestResult {
    for code in 0x40u8..=0x4F {
        let c = code as char;
        let glyph = get_glyph(c);
        if glyph.len() != 16 {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_printable_range_0x50_to_0x5f() -> TestResult {
    for code in 0x50u8..=0x5F {
        let c = code as char;
        let glyph = get_glyph(c);
        if glyph.len() != 16 {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_printable_range_0x60_to_0x6f() -> TestResult {
    for code in 0x60u8..=0x6F {
        let c = code as char;
        let glyph = get_glyph(c);
        if glyph.len() != 16 {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_printable_range_0x70_to_0x7e() -> TestResult {
    for code in 0x70u8..=0x7E {
        let c = code as char;
        let glyph = get_glyph(c);
        if glyph.len() != 16 {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_open_paren() -> TestResult {
    let glyph = get_glyph('(');
    if glyph.len() != 16 {
        return TestResult::Fail;
    }
    let has_content = glyph.iter().any(|&b| b != 0);
    if !has_content {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_close_paren() -> TestResult {
    let glyph = get_glyph(')');
    if glyph.len() != 16 {
        return TestResult::Fail;
    }
    let has_content = glyph.iter().any(|&b| b != 0);
    if !has_content {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_comma() -> TestResult {
    let glyph = get_glyph(',');
    if glyph.len() != 16 {
        return TestResult::Fail;
    }
    let has_content = glyph.iter().any(|&b| b != 0);
    if !has_content {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_double_quote() -> TestResult {
    let glyph = get_glyph('"');
    if glyph.len() != 16 {
        return TestResult::Fail;
    }
    let has_content = glyph.iter().any(|&b| b != 0);
    if !has_content {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_single_quote() -> TestResult {
    let glyph = get_glyph('\'');
    if glyph.len() != 16 {
        return TestResult::Fail;
    }
    let has_content = glyph.iter().any(|&b| b != 0);
    if !has_content {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_glyph_ampersand() -> TestResult {
    let glyph = get_glyph('&');
    if glyph.len() != 16 {
        return TestResult::Fail;
    }
    let has_content = glyph.iter().any(|&b| b != 0);
    if !has_content {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_glyph_consistent_retrieval() -> TestResult {
    let glyph1 = get_glyph('M');
    let glyph2 = get_glyph('M');
    if glyph1 != glyph2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_all_printable_ascii_have_glyphs() -> TestResult {
    for code in 0x21u8..=0x7E {
        let c = code as char;
        let glyph = get_glyph(c);
        let has_content = glyph.iter().any(|&b| b != 0);
        if !has_content {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}
