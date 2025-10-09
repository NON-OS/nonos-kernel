//! Unicode and Extended Key Mapping Table

use super::mod::{KeyCode};

pub fn map_scan_code(scan: u8, shifted: bool, layout: super::layouts::Layout) -> KeyCode {
    // TODO: Use layouts.rs and extended mappings for Unicode support
    KeyCode::Unknown
}
