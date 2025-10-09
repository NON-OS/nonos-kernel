//! Unicode and Extended Key Mapping Table

use super::mod::{KeyCode};
use super::layouts::{Layout, get_ascii_mapping};

/// Extended key mapping: scan code + layout + modifiers → KeyCode
pub fn map_scan_code(scan: u8, shifted: bool, layout: Layout) -> KeyCode {
    let ascii_table = get_ascii_mapping(layout);
    let ascii = if shifted { ascii_table[scan as usize].to_ascii_uppercase() } else { ascii_table[scan as usize] };
    match ascii {
        b'a' | b'A' => KeyCode::A,
        b'b' | b'B' => KeyCode::B,
        b'c' | b'C' => KeyCode::C,
        b'd' | b'D' => KeyCode::D,
        b'e' | b'E' => KeyCode::E,
        b'f' | b'F' => KeyCode::F,
        b'g' | b'G' => KeyCode::G,
        b'h' | b'H' => KeyCode::H,
        b'i' | b'I' => KeyCode::I,
        b'j' | b'J' => KeyCode::J,
        b'k' | b'K' => KeyCode::K,
        b'l' | b'L' => KeyCode::L,
        b'm' | b'M' => KeyCode::M,
        b'n' | b'N' => KeyCode::N,
        b'o' | b'O' => KeyCode::O,
        b'p' | b'P' => KeyCode::P,
        b'q' | b'Q' => KeyCode::Q,
        b'r' | b'R' => KeyCode::R,
        b's' | b'S' => KeyCode::S,
        b't' | b'T' => KeyCode::T,
        b'u' | b'U' => KeyCode::U,
        b'v' | b'V' => KeyCode::V,
        b'w' | b'W' => KeyCode::W,
        b'x' | b'X' => KeyCode::X,
        b'y' | b'Y' => KeyCode::Y,
        b'z' | b'Z' => KeyCode::Z,
        b'0' => KeyCode::Num0,
        b'1' => KeyCode::Num1,
        b'2' => KeyCode::Num2,
        b'3' => KeyCode::Num3,
        b'4' => KeyCode::Num4,
        b'5' => KeyCode::Num5,
        b'6' => KeyCode::Num6,
        b'7' => KeyCode::Num7,
        b'8' => KeyCode::Num8,
        b'9' => KeyCode::Num9,
        b' ' => KeyCode::Space,
        b'\n' => KeyCode::Enter,
        27 => KeyCode::Escape,
        8 => KeyCode::Backspace,
        b'\t' => KeyCode::Tab,
        _ if ascii != 0 => KeyCode::Char(ascii as char),
        _ => KeyCode::Unknown,
    }
}
