// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use super::*;
use crate::arch::x86_64::keyboard::layout::Layout;

#[test]
fn test_letter_keys() {
    assert_eq!(map_scan_code(0x1E, false, Layout::UsQwerty), KeyCode::A);
    assert_eq!(map_scan_code(0x1E, true, Layout::UsQwerty), KeyCode::A);
    assert_eq!(map_scan_code(0x30, false, Layout::UsQwerty), KeyCode::B);
}

#[test]
fn test_number_keys() {
    assert_eq!(map_scan_code(0x02, false, Layout::UsQwerty), KeyCode::Num1);
    assert_eq!(map_scan_code(0x0B, false, Layout::UsQwerty), KeyCode::Num0);
}

#[test]
fn test_special_keys() {
    assert_eq!(map_scan_code(0x01, false, Layout::UsQwerty), KeyCode::Escape);
    assert_eq!(map_scan_code(0x0E, false, Layout::UsQwerty), KeyCode::Backspace);
    assert_eq!(map_scan_code(0x0F, false, Layout::UsQwerty), KeyCode::Tab);
    assert_eq!(map_scan_code(0x1C, false, Layout::UsQwerty), KeyCode::Enter);
    assert_eq!(map_scan_code(0x39, false, Layout::UsQwerty), KeyCode::Space);
}

#[test]
fn test_function_keys() {
    assert_eq!(map_scan_code(0x3B, false, Layout::UsQwerty), KeyCode::F1);
    assert_eq!(map_scan_code(0x44, false, Layout::UsQwerty), KeyCode::F10);
    assert_eq!(map_scan_code(0x57, false, Layout::UsQwerty), KeyCode::F11);
    assert_eq!(map_scan_code(0x58, false, Layout::UsQwerty), KeyCode::F12);
}

#[test]
fn test_arrow_keys() {
    assert_eq!(map_scan_code(0x48, false, Layout::UsQwerty), KeyCode::ArrowUp);
    assert_eq!(map_scan_code(0x50, false, Layout::UsQwerty), KeyCode::ArrowDown);
    assert_eq!(map_scan_code(0x4B, false, Layout::UsQwerty), KeyCode::ArrowLeft);
    assert_eq!(map_scan_code(0x4D, false, Layout::UsQwerty), KeyCode::ArrowRight);
}

#[test]
fn test_keycode_to_ascii_basic() {
    assert_eq!(keycode_to_ascii(KeyCode::A, false), Some(b'a'));
    assert_eq!(keycode_to_ascii(KeyCode::A, true), Some(b'A'));
    assert_eq!(keycode_to_ascii(KeyCode::Num1, false), Some(b'1'));
    assert_eq!(keycode_to_ascii(KeyCode::Num1, true), Some(b'!'));
    assert_eq!(keycode_to_ascii(KeyCode::Space, false), Some(b' '));
    assert_eq!(keycode_to_ascii(KeyCode::F1, false), None);
}

#[test]
fn test_out_of_bounds() {
    assert_eq!(map_scan_code(0xFF, false, Layout::UsQwerty), KeyCode::Unknown);
    assert_eq!(map_scan_code(0x80, false, Layout::UsQwerty), KeyCode::Unknown);
}

#[test]
fn test_full_mapping() {
    let mapping = map_scan_code_full(0x1E, false, Layout::UsQwerty);
    assert_eq!(mapping.keycode, KeyCode::A);
    assert_eq!(mapping.ascii, b'a');
    assert_eq!(mapping.shifted_ascii, b'A');
}

#[test]
fn test_modifier_state() {
    let mut mods = Modifiers::NONE;
    assert!(!mods.shift());
    assert!(!mods.ctrl());

    mods.set(Modifiers::SHIFT);
    assert!(mods.shift());

    mods.set(Modifiers::CTRL);
    assert!(mods.ctrl());

    mods.clear(Modifiers::SHIFT);
    assert!(!mods.shift());
    assert!(mods.ctrl());
}

#[test]
fn test_caps_lock_effect() {
    let mods = Modifiers::from_bits(Modifiers::CAPS_LOCK);
    assert!(mods.effective_shift());

    let mods_both = Modifiers::from_bits(Modifiers::CAPS_LOCK | Modifiers::SHIFT);
    assert!(!mods_both.effective_shift());
}

#[test]
fn test_ctrl_combinations() {
    let mods = Modifiers::from_bits(Modifiers::CTRL);
    assert_eq!(keycode_to_ascii_with_mods(KeyCode::A, mods), Some(0x01));
    assert_eq!(keycode_to_ascii_with_mods(KeyCode::C, mods), Some(0x03));
    assert_eq!(keycode_to_ascii_with_mods(KeyCode::Z, mods), Some(0x1A));
}

#[test]
fn test_numpad_with_numlock() {
    let np = NumpadKey::Num5;
    assert_eq!(np.to_ascii(true), Some(b'5'));
    assert_eq!(np.to_ascii(false), None);
    assert_eq!(np.to_keycode(true), KeyCode::Num5);
    assert_eq!(np.to_keycode(false), KeyCode::Unknown);
}

#[test]
fn test_extended_scan_codes() {
    reset_extended_state();
    let result = process_scan_code(0xE0, Layout::UsQwerty);
    assert!(result.unwrap().is_none());

    let result = process_scan_code(0x48, Layout::UsQwerty);
    let mapping = result.unwrap().unwrap();
    assert_eq!(mapping.keycode, KeyCode::ArrowUp);
    assert!(mapping.extended);
}

#[test]
fn test_error_handling() {
    assert_eq!(KeymapError::InvalidScanCode.as_str(), "invalid scan code");
    assert_eq!(KeymapError::IncompleteExtended.as_str(), "incomplete extended scan code");
}

#[test]
fn test_key_mapping_get_ascii() {
    let mapping = KeyMapping::new(KeyCode::A, b'a', b'A', false, true);
    assert_eq!(mapping.get_ascii(Modifiers::NONE), Some(b'a'));
    assert_eq!(mapping.get_ascii(Modifiers::from_bits(Modifiers::SHIFT)), Some(b'A'));
}

#[test]
fn test_is_letter() {
    assert!(KeyCode::A.is_letter());
    assert!(KeyCode::Z.is_letter());
    assert!(!KeyCode::Num1.is_letter());
    assert!(!KeyCode::Space.is_letter());
}

#[test]
fn test_numpad_from_scan_code() {
    assert_eq!(NumpadKey::from_scan_code(0x47), Some(NumpadKey::Num7));
    assert_eq!(NumpadKey::from_scan_code(0x52), Some(NumpadKey::Num0));
    assert_eq!(NumpadKey::from_scan_code(0x4A), Some(NumpadKey::Subtract));
    assert_eq!(NumpadKey::from_scan_code(0xFF), None);
}
