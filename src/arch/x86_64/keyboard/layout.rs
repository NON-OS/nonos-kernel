//! Keyboard Layouts for NØNOS Kernel

#[derive(Debug, Clone, Copy)]
pub enum Layout {
    UsQwerty,
    Dvorak,
    Azerty,
    Colemak,
}

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

// Dvorak, AZERTY, Colemak tables below (fill with real mappings)
pub static DVORAK: [u8; 128] = [
    0, 27, b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0', b'[', b']', 8,
    b'\t', b'\'', b',', b'.', b'p', b'y', b'f', b'g', b'c', b'r', b'l', b'/', b'=', b'\n',
    0, b'a', b'o', b'e', b'u', b'i', b'd', b'h', b't', b'n', b's', b'-', b'`',
    0, b'\\', b';', b'q', b'j', b'k', b'x', b'b', b'm', b'w', b'v', b'z', 0,
    b'*', 0, b' ', 0,
    // Fill remaining with 0
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0,
];

pub static AZERTY: [u8; 128] = [
    0, 27, b'&', b'é', b'"', b'\'', b'(', b'-', b'è', b'_', b'ç', b'à', b')', b'=', 8,
    b'\t', b'a', b'z', b'e', b'r', b't', b'y', b'u', b'i', b'o', b'p', b'^', b'$', b'\n',
    0, b'q', b's', b'd', b'f', b'g', b'h', b'j', b'k', b'l', b'm', b'ù', b'`',
    0, b'\\', b'w', b'x', b'c', b'v', b'b', b'n', b',', b';', b':', b'!', 0,
    b'*', 0, b' ', 0,
    // Fill remaining with 0
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0,
];

pub static COLEMAK: [u8; 128] = [
    0, 27, b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9', b'0', b'-', b'=', 8,
    b'\t', b'q', b'w', b'f', b'p', b'g', b'j', b'l', b'u', b'y', b';', b'[', b']', b'\n',
    0, b'a', b'r', b's', b't', b'd', b'h', b'n', b'e', b'i', b'o', b'\'', b'`',
    0, b'\\', b'z', b'x', b'c', b'v', b'b', b'k', b'm', b',', b'.', b'/', 0,
    b'*', 0, b' ', 0,
    // Fill remaining with 0
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0,
];

/// Get ASCII mapping for given layout
pub fn get_ascii_mapping(layout: Layout) -> &'static [u8; 128] {
    match layout {
        Layout::UsQwerty => &US_QWERTY,
        Layout::Dvorak => &DVORAK,
        Layout::Azerty => &AZERTY,
        Layout::Colemak => &COLEMAK,
    }
}
