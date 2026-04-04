use crate::graphics::font::*;

#[test]
fn test_char_dimensions() {
    assert_eq!(CHAR_WIDTH, 8);
    assert_eq!(CHAR_HEIGHT, 16);
}

#[test]
fn test_char_bitmap_uppercase_letters() {
    let bitmap_a = get_char_bitmap(b'A');
    assert_eq!(bitmap_a.len(), 16);
    assert_ne!(bitmap_a[1], 0);

    let bitmap_z = get_char_bitmap(b'Z');
    assert_eq!(bitmap_z.len(), 16);
    assert_ne!(bitmap_z[1], 0);
}

#[test]
fn test_char_bitmap_lowercase_letters() {
    let bitmap_a = get_char_bitmap(b'a');
    assert_eq!(bitmap_a.len(), 16);

    let bitmap_z = get_char_bitmap(b'z');
    assert_eq!(bitmap_z.len(), 16);
}

#[test]
fn test_char_bitmap_digits() {
    for digit in b'0'..=b'9' {
        let bitmap = get_char_bitmap(digit);
        assert_eq!(bitmap.len(), 16);
    }
}

#[test]
fn test_char_bitmap_space() {
    let bitmap = get_char_bitmap(b' ');
    assert_eq!(bitmap.len(), 16);
    for row in bitmap.iter() {
        assert_eq!(*row, 0);
    }
}

#[test]
fn test_char_bitmap_punctuation() {
    let chars = [b'.', b',', b':', b';', b'-', b'_', b'=', b'+'];
    for ch in chars {
        let bitmap = get_char_bitmap(ch);
        assert_eq!(bitmap.len(), 16);
    }
}

#[test]
fn test_char_bitmap_brackets() {
    let chars = [b'(', b')', b'[', b']', b'{', b'}', b'<', b'>'];
    for ch in chars {
        let bitmap = get_char_bitmap(ch);
        assert_eq!(bitmap.len(), 16);
    }
}

#[test]
fn test_char_bitmap_symbols() {
    let chars = [b'!', b'?', b'@', b'#', b'$', b'%', b'&', b'*'];
    for ch in chars {
        let bitmap = get_char_bitmap(ch);
        assert_eq!(bitmap.len(), 16);
    }
}

#[test]
fn test_char_bitmap_quotes() {
    let chars = [b'\'', b'"', b'`'];
    for ch in chars {
        let bitmap = get_char_bitmap(ch);
        assert_eq!(bitmap.len(), 16);
    }
}

#[test]
fn test_char_bitmap_slashes() {
    let bitmap_forward = get_char_bitmap(b'/');
    let bitmap_back = get_char_bitmap(b'\\');
    let bitmap_pipe = get_char_bitmap(b'|');

    assert_eq!(bitmap_forward.len(), 16);
    assert_eq!(bitmap_back.len(), 16);
    assert_eq!(bitmap_pipe.len(), 16);
}

#[test]
fn test_char_bitmap_special() {
    let bitmap_caret = get_char_bitmap(b'^');
    let bitmap_tilde = get_char_bitmap(b'~');

    assert_eq!(bitmap_caret.len(), 16);
    assert_eq!(bitmap_tilde.len(), 16);
}

#[test]
fn test_char_bitmap_unknown() {
    let bitmap = get_char_bitmap(0x00);
    assert_eq!(bitmap.len(), 16);
    assert_ne!(bitmap[1], 0);
}

#[test]
fn test_char_bitmap_nonos_o() {
    let bitmap = get_char_bitmap(0xD8);
    assert_eq!(bitmap.len(), 16);
    assert_ne!(bitmap[1], 0);
}

#[test]
fn test_different_chars_different_bitmaps() {
    let bitmap_a = get_char_bitmap(b'A');
    let bitmap_b = get_char_bitmap(b'B');
    assert_ne!(bitmap_a, bitmap_b);
}

#[test]
fn test_case_sensitive_bitmaps() {
    let bitmap_upper = get_char_bitmap(b'A');
    let bitmap_lower = get_char_bitmap(b'a');
    assert_ne!(bitmap_upper, bitmap_lower);
}

#[test]
fn test_bitmap_has_content() {
    let non_empty_chars = [b'A', b'a', b'0', b'!', b'@'];
    for ch in non_empty_chars {
        let bitmap = get_char_bitmap(ch);
        let has_content = bitmap.iter().any(|&row| row != 0);
        assert!(has_content);
    }
}

#[test]
fn test_bitmap_within_width() {
    for ch in b'!'..=b'~' {
        let bitmap = get_char_bitmap(ch);
        assert_eq!(bitmap.len(), 16);
    }
}

#[test]
fn test_all_printable_ascii() {
    for ch in 0x20u8..=0x7E {
        let bitmap = get_char_bitmap(ch);
        assert_eq!(bitmap.len(), 16);
    }
}
