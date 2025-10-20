//! Keyboard Layouts for NØNOS Kernel

/// Supported keyboard layouts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layout {
    UsQwerty,
    Dvorak,
    Azerty,
    Colemak,
}

/// US QWERTY layout: scan codes to ASCII.
pub static US_QWERTY: [u8; 128] = [
    0, 27, b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0', b'-', b'=', 8,
    b'\t', b'q', b'w', b'e', b'r', b't', b'y', b'u', b'i', b'o', b'p', b'[', b']', b'\n',
    0, b'a', b's', b'd', b'f', b'g', b'h', b'j', b'k', b'l', b';', b'\'', b'`',
    0, b'\\', b'z', b'x', b'c', b'v', b'b', b'n', b'm', b',', b'.', b'/', 0,
    b'*', 0, b' ', 0,
    // Fill remaining with 0
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0,
];

/// Dvorak layout: scan codes to ASCII.
pub static DVORAK: [u8; 128] = [
    0, 27, b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0', b'[', b']', 8,
    b'\t', b'\'', b',', b'.', b'p', b'y', b'f', b'g', b'c', b'r', b'l', b'/', b'=', b'\n',
    0, b'a', b'o', b'e', b'u', b'i', b'd', b'h', b't', b'n', b's', b'-', b'`',
    0, b'\\', b';', b'q', b'j', b'k', b'x', b'b', b'm', b'w', b'v', b'z', 0,
    b'*', 0, b' ', 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0,
];

/// AZERTY layout: scan codes to ASCII.
pub static AZERTY: [u8; 128] = [
    0, 27, b'&', b'\xE9', b'"', b'\'', b'(', b'-', b'\xE8', b'_', b'\xE7', b'\xE0', b')', b'=', 8,
    b'\t', b'a', b'z', b'e', b'r', b't', b'y', b'u', b'i', b'o', b'p', b'^', b'$', b'\n',
    0, b'q', b's', b'd', b'f', b'g', b'h', b'j', b'k', b'l', b'm', b'\xF9', b'`',
    0, b'\\', b'w', b'x', b'c', b'v', b'b', b'n', b',', b';', b':', b'!', 0,
    b'*', 0, b' ', 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0,
];

/// Colemak layout: scan codes to ASCII.
pub static COLEMAK: [u8; 128] = [
    0, 27, b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0', b'-', b'=', 8,
    b'\t', b'q', b'w', b'f', b'p', b'g', b'j', b'l', b'u', b'y', b';', b'[', b']', b'\n',
    0, b'a', b'r', b's', b't', b'd', b'h', b'n', b'e', b'i', b'o', b'\'', b'`',
    0, b'\\', b'z', b'x', b'c', b'v', b'b', b'k', b'm', b',', b'.', b'/', 0,
    b'*', 0, b' ', 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0,
];

/// ASCII mapping for the given layout.
pub fn get_ascii_mapping(layout: Layout) -> &'static [u8; 128] {
    match layout {
        Layout::UsQwerty => &US_QWERTY,
        Layout::Dvorak => &DVORAK,
        Layout::Azerty => &AZERTY,
        Layout::Colemak => &COLEMAK,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_us_qwerty_mapping() {
        assert_eq!(US_QWERTY[2], b'1');
        assert_eq!(US_QWERTY[30], b'a');
        assert_eq!(US_QWERTY[57], b' ');
    }

    #[test]
    fn test_dvorak_mapping() {
        assert_eq!(DVORAK[2], b'1');
        assert_eq!(DVORAK[30], b'a');
        assert_eq!(DVORAK[18], b',');
    }

    #[test]
    fn test_azerty_mapping() {
        assert_eq!(AZERTY[2], b'&');
        assert_eq!(AZERTY[16], b'a');
        assert_eq!(AZERTY[44], b'!');
    }

    #[test]
    fn test_colemak_mapping() {
        assert_eq!(COLEMAK[2], b'1');
        assert_eq!(COLEMAK[30], b'a');
        assert_eq!(COLEMAK[18], b'f');
    }

    #[test]
    fn test_get_ascii_mapping() {
        assert_eq!(get_ascii_mapping(Layout::UsQwerty), &US_QWERTY);
        assert_eq!(get_ascii_mapping(Layout::Dvorak), &DVORAK);
        assert_eq!(get_ascii_mapping(Layout::Azerty), &AZERTY);
        assert_eq!(get_ascii_mapping(Layout::Colemak), &COLEMAK);
    }
}
