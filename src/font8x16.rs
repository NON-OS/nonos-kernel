#![allow(dead_code)]

pub const W: usize = 8;
pub const H: usize = 16;

/// Minimal 8×16 glyphs we actually need right now.
/// Each glyph = 16 bytes, MSB is the left-most pixel of the 8-pixel row.
/// (White = bit=1). Characters not defined return all-zeros.
const N_GLYPH: [u8; 16] = [
    0b11000011,
    0b11100011,
    0b11110011,
    0b11011011,
    0b11001111,
    0b11000111,
    0b11000011,
    0b11000011,
    0b11000011,
    0b11000011,
    0b11000011,
    0b11000111,
    0b11001111,
    0b11011011,
    0b11110011,
    0b11100011,
];

const O_GLYPH: [u8; 16] = [
    0b00111100,
    0b01100110,
    0b11000011,
    0b11000011,
    0b11000011,
    0b11000011,
    0b11000011,
    0b11000011,
    0b11000011,
    0b11000011,
    0b11000011,
    0b11000011,
    0b11000011,
    0b01100110,
    0b00111100,
    0b00000000,
];

const S_GLYPH: [u8; 16] = [
    0b00111110,
    0b01100000,
    0b11000000,
    0b11000000,
    0b01111100,
    0b00000110,
    0b00000011,
    0b00000011,
    0b00000011,
    0b11000011,
    0b11000011,
    0b01100011,
    0b00111110,
    0b00000000,
    0b00000000,
    0b00000000,
];

#[inline]
pub fn glyph(c: u8) -> [u8; 16] {
    match c {
        b'N' => N_GLYPH,
        b'O' => O_GLYPH,
        b'S' => S_GLYPH,
        _ => [0u8; 16],
    }
}
