use crate::graphics::window::state::*;
use crate::test::framework::TestResult;

pub(crate) fn test_window_type_values() -> TestResult {
    if WindowType::None as u8 != 0 {
        return TestResult::Fail;
    }
    if WindowType::FileManager as u8 != 1 {
        return TestResult::Fail;
    }
    if WindowType::Calculator as u8 != 2 {
        return TestResult::Fail;
    }
    if WindowType::TextEditor as u8 != 3 {
        return TestResult::Fail;
    }
    if WindowType::Settings as u8 != 4 {
        return TestResult::Fail;
    }
    if WindowType::About as u8 != 5 {
        return TestResult::Fail;
    }
    if WindowType::ProcessManager as u8 != 6 {
        return TestResult::Fail;
    }
    if WindowType::Browser as u8 != 7 {
        return TestResult::Fail;
    }
    if WindowType::Terminal as u8 != 8 {
        return TestResult::Fail;
    }
    if WindowType::Wallet as u8 != 9 {
        return TestResult::Fail;
    }
    if WindowType::Ecosystem as u8 != 10 {
        return TestResult::Fail;
    }
    if WindowType::Marketplace as u8 != 11 {
        return TestResult::Fail;
    }
    if WindowType::Developer as u8 != 12 {
        return TestResult::Fail;
    }
    if WindowType::Agents as u8 != 13 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_window_type_from_u32() -> TestResult {
    if window_type_from_u32(0) != WindowType::None {
        return TestResult::Fail;
    }
    if window_type_from_u32(1) != WindowType::FileManager {
        return TestResult::Fail;
    }
    if window_type_from_u32(2) != WindowType::Calculator {
        return TestResult::Fail;
    }
    if window_type_from_u32(3) != WindowType::TextEditor {
        return TestResult::Fail;
    }
    if window_type_from_u32(4) != WindowType::Settings {
        return TestResult::Fail;
    }
    if window_type_from_u32(5) != WindowType::About {
        return TestResult::Fail;
    }
    if window_type_from_u32(6) != WindowType::ProcessManager {
        return TestResult::Fail;
    }
    if window_type_from_u32(7) != WindowType::Browser {
        return TestResult::Fail;
    }
    if window_type_from_u32(8) != WindowType::Terminal {
        return TestResult::Fail;
    }
    if window_type_from_u32(9) != WindowType::Wallet {
        return TestResult::Fail;
    }
    if window_type_from_u32(10) != WindowType::Ecosystem {
        return TestResult::Fail;
    }
    if window_type_from_u32(11) != WindowType::Marketplace {
        return TestResult::Fail;
    }
    if window_type_from_u32(12) != WindowType::Developer {
        return TestResult::Fail;
    }
    if window_type_from_u32(13) != WindowType::Agents {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_window_type_from_u32_invalid() -> TestResult {
    if window_type_from_u32(14) != WindowType::None {
        return TestResult::Fail;
    }
    if window_type_from_u32(100) != WindowType::None {
        return TestResult::Fail;
    }
    if window_type_from_u32(255) != WindowType::None {
        return TestResult::Fail;
    }
    if window_type_from_u32(u32::MAX) != WindowType::None {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_window_type_equality() -> TestResult {
    if WindowType::FileManager != WindowType::FileManager {
        return TestResult::Fail;
    }
    if WindowType::FileManager == WindowType::Calculator {
        return TestResult::Fail;
    }
    if WindowType::None == WindowType::Terminal {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_snap_zone_values() -> TestResult {
    if SnapZone::None as u8 != 0 {
        return TestResult::Fail;
    }
    if SnapZone::Left as u8 != 1 {
        return TestResult::Fail;
    }
    if SnapZone::Right as u8 != 2 {
        return TestResult::Fail;
    }
    if SnapZone::Top as u8 != 3 {
        return TestResult::Fail;
    }
    if SnapZone::TopLeft as u8 != 4 {
        return TestResult::Fail;
    }
    if SnapZone::TopRight as u8 != 5 {
        return TestResult::Fail;
    }
    if SnapZone::BottomLeft as u8 != 6 {
        return TestResult::Fail;
    }
    if SnapZone::BottomRight as u8 != 7 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_snap_zone_from_u8() -> TestResult {
    if SnapZone::from_u8(0) != SnapZone::None {
        return TestResult::Fail;
    }
    if SnapZone::from_u8(1) != SnapZone::Left {
        return TestResult::Fail;
    }
    if SnapZone::from_u8(2) != SnapZone::Right {
        return TestResult::Fail;
    }
    if SnapZone::from_u8(3) != SnapZone::Top {
        return TestResult::Fail;
    }
    if SnapZone::from_u8(4) != SnapZone::TopLeft {
        return TestResult::Fail;
    }
    if SnapZone::from_u8(5) != SnapZone::TopRight {
        return TestResult::Fail;
    }
    if SnapZone::from_u8(6) != SnapZone::BottomLeft {
        return TestResult::Fail;
    }
    if SnapZone::from_u8(7) != SnapZone::BottomRight {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_snap_zone_from_u8_invalid() -> TestResult {
    if SnapZone::from_u8(8) != SnapZone::None {
        return TestResult::Fail;
    }
    if SnapZone::from_u8(100) != SnapZone::None {
        return TestResult::Fail;
    }
    if SnapZone::from_u8(255) != SnapZone::None {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_snap_zone_default() -> TestResult {
    let zone: SnapZone = Default::default();
    if zone != SnapZone::None {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_max_windows_constant() -> TestResult {
    if MAX_WINDOWS != 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_window_padding_constant() -> TestResult {
    if WINDOW_PADDING != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_windows_array_length() -> TestResult {
    if WINDOWS.len() != MAX_WINDOWS {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_window_type_copy() -> TestResult {
    let wt1 = WindowType::Browser;
    let wt2 = wt1;
    if wt1 != wt2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_snap_zone_copy() -> TestResult {
    let sz1 = SnapZone::TopRight;
    let sz2 = sz1;
    if sz1 != sz2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_window_type_roundtrip() -> TestResult {
    for i in 0u32..14 {
        let wtype = window_type_from_u32(i);
        if i == 0 {
            if wtype != WindowType::None {
                return TestResult::Fail;
            }
        } else {
            if wtype as u32 != i {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_snap_zone_roundtrip() -> TestResult {
    for i in 0u8..8 {
        let zone = SnapZone::from_u8(i);
        if zone as u8 != i {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}
