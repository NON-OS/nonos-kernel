use crate::graphics::window::state::*;

#[test]
fn test_window_type_values() {
    assert_eq!(WindowType::None as u8, 0);
    assert_eq!(WindowType::FileManager as u8, 1);
    assert_eq!(WindowType::Calculator as u8, 2);
    assert_eq!(WindowType::TextEditor as u8, 3);
    assert_eq!(WindowType::Settings as u8, 4);
    assert_eq!(WindowType::About as u8, 5);
    assert_eq!(WindowType::ProcessManager as u8, 6);
    assert_eq!(WindowType::Browser as u8, 7);
    assert_eq!(WindowType::Terminal as u8, 8);
    assert_eq!(WindowType::Wallet as u8, 9);
    assert_eq!(WindowType::Ecosystem as u8, 10);
    assert_eq!(WindowType::Marketplace as u8, 11);
    assert_eq!(WindowType::Developer as u8, 12);
    assert_eq!(WindowType::Agents as u8, 13);
}

#[test]
fn test_window_type_from_u32() {
    assert_eq!(window_type_from_u32(0), WindowType::None);
    assert_eq!(window_type_from_u32(1), WindowType::FileManager);
    assert_eq!(window_type_from_u32(2), WindowType::Calculator);
    assert_eq!(window_type_from_u32(3), WindowType::TextEditor);
    assert_eq!(window_type_from_u32(4), WindowType::Settings);
    assert_eq!(window_type_from_u32(5), WindowType::About);
    assert_eq!(window_type_from_u32(6), WindowType::ProcessManager);
    assert_eq!(window_type_from_u32(7), WindowType::Browser);
    assert_eq!(window_type_from_u32(8), WindowType::Terminal);
    assert_eq!(window_type_from_u32(9), WindowType::Wallet);
    assert_eq!(window_type_from_u32(10), WindowType::Ecosystem);
    assert_eq!(window_type_from_u32(11), WindowType::Marketplace);
    assert_eq!(window_type_from_u32(12), WindowType::Developer);
    assert_eq!(window_type_from_u32(13), WindowType::Agents);
}

#[test]
fn test_window_type_from_u32_invalid() {
    assert_eq!(window_type_from_u32(14), WindowType::None);
    assert_eq!(window_type_from_u32(100), WindowType::None);
    assert_eq!(window_type_from_u32(255), WindowType::None);
    assert_eq!(window_type_from_u32(u32::MAX), WindowType::None);
}

#[test]
fn test_window_type_equality() {
    assert_eq!(WindowType::FileManager, WindowType::FileManager);
    assert_ne!(WindowType::FileManager, WindowType::Calculator);
    assert_ne!(WindowType::None, WindowType::Terminal);
}

#[test]
fn test_snap_zone_values() {
    assert_eq!(SnapZone::None as u8, 0);
    assert_eq!(SnapZone::Left as u8, 1);
    assert_eq!(SnapZone::Right as u8, 2);
    assert_eq!(SnapZone::Top as u8, 3);
    assert_eq!(SnapZone::TopLeft as u8, 4);
    assert_eq!(SnapZone::TopRight as u8, 5);
    assert_eq!(SnapZone::BottomLeft as u8, 6);
    assert_eq!(SnapZone::BottomRight as u8, 7);
}

#[test]
fn test_snap_zone_from_u8() {
    assert_eq!(SnapZone::from_u8(0), SnapZone::None);
    assert_eq!(SnapZone::from_u8(1), SnapZone::Left);
    assert_eq!(SnapZone::from_u8(2), SnapZone::Right);
    assert_eq!(SnapZone::from_u8(3), SnapZone::Top);
    assert_eq!(SnapZone::from_u8(4), SnapZone::TopLeft);
    assert_eq!(SnapZone::from_u8(5), SnapZone::TopRight);
    assert_eq!(SnapZone::from_u8(6), SnapZone::BottomLeft);
    assert_eq!(SnapZone::from_u8(7), SnapZone::BottomRight);
}

#[test]
fn test_snap_zone_from_u8_invalid() {
    assert_eq!(SnapZone::from_u8(8), SnapZone::None);
    assert_eq!(SnapZone::from_u8(100), SnapZone::None);
    assert_eq!(SnapZone::from_u8(255), SnapZone::None);
}

#[test]
fn test_snap_zone_default() {
    let zone: SnapZone = Default::default();
    assert_eq!(zone, SnapZone::None);
}

#[test]
fn test_max_windows_constant() {
    assert_eq!(MAX_WINDOWS, 8);
}

#[test]
fn test_window_padding_constant() {
    assert_eq!(WINDOW_PADDING, 2);
}

#[test]
fn test_windows_array_length() {
    assert_eq!(WINDOWS.len(), MAX_WINDOWS);
}

#[test]
fn test_window_type_copy() {
    let wt1 = WindowType::Browser;
    let wt2 = wt1;
    assert_eq!(wt1, wt2);
}

#[test]
fn test_snap_zone_copy() {
    let sz1 = SnapZone::TopRight;
    let sz2 = sz1;
    assert_eq!(sz1, sz2);
}

#[test]
fn test_window_type_roundtrip() {
    for i in 0u32..14 {
        let wtype = window_type_from_u32(i);
        if i == 0 {
            assert_eq!(wtype, WindowType::None);
        } else {
            assert_eq!(wtype as u32, i);
        }
    }
}

#[test]
fn test_snap_zone_roundtrip() {
    for i in 0u8..8 {
        let zone = SnapZone::from_u8(i);
        assert_eq!(zone as u8, i);
    }
}
