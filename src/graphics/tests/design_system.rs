use crate::graphics::design_system::{borders, colors, spacing};
use crate::test::framework::TestResult;

pub(crate) fn test_border_radius_values() -> TestResult {
    if borders::RADIUS_NONE != 0 {
        return TestResult::Fail;
    }
    if borders::RADIUS_XS != 2 {
        return TestResult::Fail;
    }
    if borders::RADIUS_SM != 4 {
        return TestResult::Fail;
    }
    if borders::RADIUS_MD != 8 {
        return TestResult::Fail;
    }
    if borders::RADIUS_LG != 12 {
        return TestResult::Fail;
    }
    if borders::RADIUS_XL != 16 {
        return TestResult::Fail;
    }
    if borders::RADIUS_2XL != 24 {
        return TestResult::Fail;
    }
    if borders::RADIUS_FULL != 9999 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_border_component_radius() -> TestResult {
    if borders::RADIUS_WINDOW != borders::RADIUS_LG {
        return TestResult::Fail;
    }
    if borders::RADIUS_BUTTON != borders::RADIUS_MD {
        return TestResult::Fail;
    }
    if borders::RADIUS_INPUT != borders::RADIUS_MD {
        return TestResult::Fail;
    }
    if borders::RADIUS_CARD != borders::RADIUS_LG {
        return TestResult::Fail;
    }
    if borders::RADIUS_DIALOG != borders::RADIUS_XL {
        return TestResult::Fail;
    }
    if borders::RADIUS_TOOLTIP != borders::RADIUS_SM {
        return TestResult::Fail;
    }
    if borders::RADIUS_BADGE != borders::RADIUS_SM {
        return TestResult::Fail;
    }
    if borders::RADIUS_DOCK != borders::RADIUS_XL {
        return TestResult::Fail;
    }
    if borders::RADIUS_MENU != borders::RADIUS_MD {
        return TestResult::Fail;
    }
    if borders::RADIUS_SCROLLBAR != borders::RADIUS_SM {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_border_width_values() -> TestResult {
    if borders::BORDER_NONE != 0 {
        return TestResult::Fail;
    }
    if borders::BORDER_THIN != 1 {
        return TestResult::Fail;
    }
    if borders::BORDER_NORMAL != 2 {
        return TestResult::Fail;
    }
    if borders::BORDER_THICK != 3 {
        return TestResult::Fail;
    }
    if borders::BORDER_FOCUS_WIDTH != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_clamp_radius_no_clamp() -> TestResult {
    if borders::clamp_radius(8, 100, 100) != 8 {
        return TestResult::Fail;
    }
    if borders::clamp_radius(10, 50, 100) != 10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_clamp_radius_clamps_to_width() -> TestResult {
    if borders::clamp_radius(100, 40, 100) != 20 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_clamp_radius_clamps_to_height() -> TestResult {
    if borders::clamp_radius(100, 100, 40) != 20 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_clamp_radius_at_limit() -> TestResult {
    if borders::clamp_radius(25, 50, 100) != 25 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_pill_true() -> TestResult {
    if !borders::is_pill(50, 100, 100) {
        return TestResult::Fail;
    }
    if !borders::is_pill(25, 50, 100) {
        return TestResult::Fail;
    }
    if !borders::is_pill(100, 50, 100) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_pill_false() -> TestResult {
    if borders::is_pill(10, 100, 100) {
        return TestResult::Fail;
    }
    if borders::is_pill(5, 50, 100) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_pill_boundary() -> TestResult {
    if borders::is_pill(24, 50, 100) {
        return TestResult::Fail;
    }
    if !borders::is_pill(25, 50, 100) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_spacing_unit() -> TestResult {
    if spacing::scale::SPACE_UNIT != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_spacing_scale() -> TestResult {
    if spacing::scale::SPACE_0 != 0 {
        return TestResult::Fail;
    }
    if spacing::scale::SPACE_1 != 4 {
        return TestResult::Fail;
    }
    if spacing::scale::SPACE_2 != 8 {
        return TestResult::Fail;
    }
    if spacing::scale::SPACE_3 != 12 {
        return TestResult::Fail;
    }
    if spacing::scale::SPACE_4 != 16 {
        return TestResult::Fail;
    }
    if spacing::scale::SPACE_5 != 20 {
        return TestResult::Fail;
    }
    if spacing::scale::SPACE_6 != 24 {
        return TestResult::Fail;
    }
    if spacing::scale::SPACE_8 != 32 {
        return TestResult::Fail;
    }
    if spacing::scale::SPACE_10 != 40 {
        return TestResult::Fail;
    }
    if spacing::scale::SPACE_12 != 48 {
        return TestResult::Fail;
    }
    if spacing::scale::SPACE_16 != 64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_spacing_scale_multiples() -> TestResult {
    if spacing::scale::SPACE_1 != spacing::scale::SPACE_UNIT * 1 {
        return TestResult::Fail;
    }
    if spacing::scale::SPACE_2 != spacing::scale::SPACE_UNIT * 2 {
        return TestResult::Fail;
    }
    if spacing::scale::SPACE_4 != spacing::scale::SPACE_UNIT * 4 {
        return TestResult::Fail;
    }
    if spacing::scale::SPACE_8 != spacing::scale::SPACE_UNIT * 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_semantic_accent_color() -> TestResult {
    if colors::semantic::ACCENT != 0xFF00D4FF {
        return TestResult::Fail;
    }
    if colors::semantic::ACCENT_HOVER != 0xFF40E0FF {
        return TestResult::Fail;
    }
    if colors::semantic::ACCENT_DIM != 0xFF007090 {
        return TestResult::Fail;
    }
    if colors::semantic::ACCENT_GLOW != 0xFF60E8FF {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_semantic_success_color() -> TestResult {
    if colors::semantic::SUCCESS != 0xFF22C55E {
        return TestResult::Fail;
    }
    if colors::semantic::SUCCESS_GLOW != 0xFF4ADE80 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_semantic_warning_color() -> TestResult {
    if colors::semantic::WARNING != 0xFFF59E0B {
        return TestResult::Fail;
    }
    if colors::semantic::WARNING_GLOW != 0xFFFBBF24 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_semantic_error_color() -> TestResult {
    if colors::semantic::ERROR != 0xFFEF4444 {
        return TestResult::Fail;
    }
    if colors::semantic::ERROR_GLOW != 0xFFF87171 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_semantic_info_color() -> TestResult {
    if colors::semantic::INFO != 0xFF3B82F6 {
        return TestResult::Fail;
    }
    if colors::semantic::INFO_GLOW != 0xFF60A5FA {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_semantic_other_colors() -> TestResult {
    if colors::semantic::PURPLE != 0xFFA855F7 {
        return TestResult::Fail;
    }
    if colors::semantic::PURPLE_GLOW != 0xFFC084FC {
        return TestResult::Fail;
    }
    if colors::semantic::PINK != 0xFFEC4899 {
        return TestResult::Fail;
    }
    if colors::semantic::CYAN != 0xFF06B6D4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_border_radius_hierarchy() -> TestResult {
    if !(borders::RADIUS_XS < borders::RADIUS_SM) {
        return TestResult::Fail;
    }
    if !(borders::RADIUS_SM < borders::RADIUS_MD) {
        return TestResult::Fail;
    }
    if !(borders::RADIUS_MD < borders::RADIUS_LG) {
        return TestResult::Fail;
    }
    if !(borders::RADIUS_LG < borders::RADIUS_XL) {
        return TestResult::Fail;
    }
    if !(borders::RADIUS_XL < borders::RADIUS_2XL) {
        return TestResult::Fail;
    }
    if !(borders::RADIUS_2XL < borders::RADIUS_FULL) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_border_width_hierarchy() -> TestResult {
    if !(borders::BORDER_NONE < borders::BORDER_THIN) {
        return TestResult::Fail;
    }
    if !(borders::BORDER_THIN < borders::BORDER_NORMAL) {
        return TestResult::Fail;
    }
    if !(borders::BORDER_NORMAL < borders::BORDER_THICK) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_spacing_hierarchy() -> TestResult {
    if !(spacing::scale::SPACE_0 < spacing::scale::SPACE_1) {
        return TestResult::Fail;
    }
    if !(spacing::scale::SPACE_1 < spacing::scale::SPACE_2) {
        return TestResult::Fail;
    }
    if !(spacing::scale::SPACE_2 < spacing::scale::SPACE_3) {
        return TestResult::Fail;
    }
    if !(spacing::scale::SPACE_3 < spacing::scale::SPACE_4) {
        return TestResult::Fail;
    }
    if !(spacing::scale::SPACE_4 < spacing::scale::SPACE_5) {
        return TestResult::Fail;
    }
    if !(spacing::scale::SPACE_5 < spacing::scale::SPACE_6) {
        return TestResult::Fail;
    }
    if !(spacing::scale::SPACE_6 < spacing::scale::SPACE_8) {
        return TestResult::Fail;
    }
    if !(spacing::scale::SPACE_8 < spacing::scale::SPACE_10) {
        return TestResult::Fail;
    }
    if !(spacing::scale::SPACE_10 < spacing::scale::SPACE_12) {
        return TestResult::Fail;
    }
    if !(spacing::scale::SPACE_12 < spacing::scale::SPACE_16) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_semantic_colors_opaque() -> TestResult {
    if (colors::semantic::ACCENT >> 24) & 0xFF != 0xFF {
        return TestResult::Fail;
    }
    if (colors::semantic::SUCCESS >> 24) & 0xFF != 0xFF {
        return TestResult::Fail;
    }
    if (colors::semantic::WARNING >> 24) & 0xFF != 0xFF {
        return TestResult::Fail;
    }
    if (colors::semantic::ERROR >> 24) & 0xFF != 0xFF {
        return TestResult::Fail;
    }
    if (colors::semantic::INFO >> 24) & 0xFF != 0xFF {
        return TestResult::Fail;
    }
    TestResult::Pass
}
