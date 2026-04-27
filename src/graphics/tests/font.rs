use crate::graphics::font::*;
use crate::test::framework::TestResult;

pub(crate) fn test_char_dimensions() -> TestResult {
    if CHAR_WIDTH != 8 {
        return TestResult::Fail;
    }
    if CHAR_HEIGHT != 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_char_bitmap_uppercase_letters() -> TestResult {
    let bitmap_a = get_char_bitmap(b'A');
    if bitmap_a.len() != 16 {
        return TestResult::Fail;
    }
    if bitmap_a[1] == 0 {
        return TestResult::Fail;
    }

    let bitmap_z = get_char_bitmap(b'Z');
    if bitmap_z.len() != 16 {
        return TestResult::Fail;
    }
    if bitmap_z[1] == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_char_bitmap_lowercase_letters() -> TestResult {
    let bitmap_a = get_char_bitmap(b'a');
    if bitmap_a.len() != 16 {
        return TestResult::Fail;
    }

    let bitmap_z = get_char_bitmap(b'z');
    if bitmap_z.len() != 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_char_bitmap_digits() -> TestResult {
    for digit in b'0'..=b'9' {
        let bitmap = get_char_bitmap(digit);
        if bitmap.len() != 16 {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_char_bitmap_space() -> TestResult {
    let bitmap = get_char_bitmap(b' ');
    if bitmap.len() != 16 {
        return TestResult::Fail;
    }
    for row in bitmap.iter() {
        if *row != 0 {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_char_bitmap_punctuation() -> TestResult {
    let chars = [b'.', b',', b':', b';', b'-', b'_', b'=', b'+'];
    for ch in chars {
        let bitmap = get_char_bitmap(ch);
        if bitmap.len() != 16 {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_char_bitmap_brackets() -> TestResult {
    let chars = [b'(', b')', b'[', b']', b'{', b'}', b'<', b'>'];
    for ch in chars {
        let bitmap = get_char_bitmap(ch);
        if bitmap.len() != 16 {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_char_bitmap_symbols() -> TestResult {
    let chars = [b'!', b'?', b'@', b'#', b'$', b'%', b'&', b'*'];
    for ch in chars {
        let bitmap = get_char_bitmap(ch);
        if bitmap.len() != 16 {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_char_bitmap_quotes() -> TestResult {
    let chars = [b'\'', b'"', b'`'];
    for ch in chars {
        let bitmap = get_char_bitmap(ch);
        if bitmap.len() != 16 {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_char_bitmap_slashes() -> TestResult {
    let bitmap_forward = get_char_bitmap(b'/');
    let bitmap_back = get_char_bitmap(b'\\');
    let bitmap_pipe = get_char_bitmap(b'|');

    if bitmap_forward.len() != 16 {
        return TestResult::Fail;
    }
    if bitmap_back.len() != 16 {
        return TestResult::Fail;
    }
    if bitmap_pipe.len() != 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_char_bitmap_special() -> TestResult {
    let bitmap_caret = get_char_bitmap(b'^');
    let bitmap_tilde = get_char_bitmap(b'~');

    if bitmap_caret.len() != 16 {
        return TestResult::Fail;
    }
    if bitmap_tilde.len() != 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_char_bitmap_unknown() -> TestResult {
    let bitmap = get_char_bitmap(0x00);
    if bitmap.len() != 16 {
        return TestResult::Fail;
    }
    if bitmap[1] == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_char_bitmap_nonos_o() -> TestResult {
    let bitmap = get_char_bitmap(0xD8);
    if bitmap.len() != 16 {
        return TestResult::Fail;
    }
    if bitmap[1] == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_different_chars_different_bitmaps() -> TestResult {
    let bitmap_a = get_char_bitmap(b'A');
    let bitmap_b = get_char_bitmap(b'B');
    if bitmap_a == bitmap_b {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_case_sensitive_bitmaps() -> TestResult {
    let bitmap_upper = get_char_bitmap(b'A');
    let bitmap_lower = get_char_bitmap(b'a');
    if bitmap_upper == bitmap_lower {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_bitmap_has_content() -> TestResult {
    let non_empty_chars = [b'A', b'a', b'0', b'!', b'@'];
    for ch in non_empty_chars {
        let bitmap = get_char_bitmap(ch);
        let has_content = bitmap.iter().any(|&row| row != 0);
        if !has_content {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_bitmap_within_width() -> TestResult {
    for ch in b'!'..=b'~' {
        let bitmap = get_char_bitmap(ch);
        if bitmap.len() != 16 {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_all_printable_ascii() -> TestResult {
    for ch in 0x20u8..=0x7E {
        let bitmap = get_char_bitmap(ch);
        if bitmap.len() != 16 {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}
