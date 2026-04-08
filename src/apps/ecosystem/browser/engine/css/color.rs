extern crate alloc;
use super::types::CssColor;
use super::color_rgb::parse_rgb_function;
use super::color_named::parse_named_color;

pub fn parse_color(input: &str) -> Option<CssColor> {
    let s = input.trim();
    if s.starts_with('#') {
        return parse_hex_color(&s[1..]);
    }
    if s.starts_with("rgb") {
        return parse_rgb_function(s);
    }
    parse_named_color(s)
}

fn parse_hex_color(hex: &str) -> Option<CssColor> {
    match hex.len() {
        3 => {
            let r = parse_hex_digit(hex.as_bytes()[0])? * 17;
            let g = parse_hex_digit(hex.as_bytes()[1])? * 17;
            let b = parse_hex_digit(hex.as_bytes()[2])? * 17;
            Some(CssColor::rgb(r, g, b))
        }
        6 => {
            let r = parse_hex_byte(&hex[0..2])?;
            let g = parse_hex_byte(&hex[2..4])?;
            let b = parse_hex_byte(&hex[4..6])?;
            Some(CssColor::rgb(r, g, b))
        }
        8 => {
            let r = parse_hex_byte(&hex[0..2])?;
            let g = parse_hex_byte(&hex[2..4])?;
            let b = parse_hex_byte(&hex[4..6])?;
            let a = parse_hex_byte(&hex[6..8])?;
            Some(CssColor::rgba(r, g, b, a))
        }
        _ => None,
    }
}

fn parse_hex_digit(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn parse_hex_byte(s: &str) -> Option<u8> {
    let hi = parse_hex_digit(s.as_bytes()[0])?;
    let lo = parse_hex_digit(s.as_bytes()[1])?;
    Some(hi * 16 + lo)
}
