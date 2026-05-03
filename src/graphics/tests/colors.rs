use crate::display::framebuffer::colors::*;
use crate::test::framework::TestResult;

pub(crate) fn test_brand_accent_colors() -> TestResult {
    if COLOR_ACCENT != 0xFF66FFFF {
        return TestResult::Fail;
    }
    if COLOR_ACCENT_DIM != 0xFF4DCCCC {
        return TestResult::Fail;
    }
    if COLOR_ACCENT_GLOW != 0x4066FFFF {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_brand_secondary_colors() -> TestResult {
    if COLOR_SECONDARY != 0xFF2E5C5C {
        return TestResult::Fail;
    }
    if COLOR_SECONDARY_DIM != 0xFF1E4040 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_background_colors() -> TestResult {
    if COLOR_BG != 0xFF080C10 {
        return TestResult::Fail;
    }
    if COLOR_BG_GRADIENT_TOP != 0xFF0A1014 {
        return TestResult::Fail;
    }
    if COLOR_BG_GRADIENT_BOTTOM != 0xFF050808 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_panel_colors() -> TestResult {
    if COLOR_PANEL != 0xFF0E1418 {
        return TestResult::Fail;
    }
    if COLOR_PANEL_HOVER != 0xFF141C22 {
        return TestResult::Fail;
    }
    if COLOR_PANEL_ACTIVE != 0xFF0A0E12 {
        return TestResult::Fail;
    }
    if COLOR_PANEL_BORDER != 0xFF1A2428 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_text_colors() -> TestResult {
    if COLOR_TEXT != 0xFF66FFFF {
        return TestResult::Fail;
    }
    if COLOR_TEXT_WHITE != 0xFFF0F6FC {
        return TestResult::Fail;
    }
    if COLOR_TEXT_DIM != 0xFF6E8088 {
        return TestResult::Fail;
    }
    if COLOR_TEXT_MUTED != 0xFF3A4448 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_terminal_colors() -> TestResult {
    if COLOR_TERMINAL_BG != 0xFF0A0E12 {
        return TestResult::Fail;
    }
    if COLOR_TERMINAL_BORDER != 0xFF1A2428 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_semantic_colors() -> TestResult {
    if COLOR_GREEN != 0xFF00E676 {
        return TestResult::Fail;
    }
    if COLOR_RED != 0xFFFF5252 {
        return TestResult::Fail;
    }
    if COLOR_YELLOW != 0xFFFFD740 {
        return TestResult::Fail;
    }
    if COLOR_ORANGE != 0xFFFF9100 {
        return TestResult::Fail;
    }
    if COLOR_PURPLE != 0xFFBB86FC {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ui_state_colors() -> TestResult {
    if COLOR_SUCCESS != 0xFF00E676 {
        return TestResult::Fail;
    }
    if COLOR_ERROR != 0xFFFF5252 {
        return TestResult::Fail;
    }
    if COLOR_WARNING != 0xFFFFD740 {
        return TestResult::Fail;
    }
    if COLOR_INFO != 0xFF66FFFF {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cursor_colors() -> TestResult {
    if COLOR_CURSOR != 0xFF66FFFF {
        return TestResult::Fail;
    }
    if COLOR_SELECTION != 0x4066FFFF {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_grid_colors() -> TestResult {
    if COLOR_GRID != 0xFF0C1014 {
        return TestResult::Fail;
    }
    if COLOR_GRID_ACCENT != 0xFF101820 {
        return TestResult::Fail;
    }
    if COLOR_GLOW_SOFT != 0x1866FFFF {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_legacy_aliases() -> TestResult {
    if COLOR_FG != COLOR_TEXT {
        return TestResult::Fail;
    }
    if COLOR_WHITE != 0xFFFFFFFF {
        return TestResult::Fail;
    }
    if COLOR_BLACK != 0xFF000000 {
        return TestResult::Fail;
    }
    if COLOR_BLUE != COLOR_ACCENT {
        return TestResult::Fail;
    }
    if COLOR_GRAY != 0xFF707070 {
        return TestResult::Fail;
    }
    if COLOR_DARK_GRAY != 0xFF383838 {
        return TestResult::Fail;
    }
    if COLOR_LIGHT_GRAY != 0xFFB0B0B0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_menu_aliases() -> TestResult {
    if COLOR_MENU_BG != COLOR_PANEL {
        return TestResult::Fail;
    }
    if COLOR_DOCK_BG != COLOR_PANEL {
        return TestResult::Fail;
    }
    if COLOR_WINDOW_BG != COLOR_PANEL {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_title_aliases() -> TestResult {
    if COLOR_TITLE_BG != COLOR_PANEL_ACTIVE {
        return TestResult::Fail;
    }
    if COLOR_TITLE_FG != COLOR_TEXT_WHITE {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_color_format_argb() -> TestResult {
    let color = COLOR_ACCENT;
    let alpha = (color >> 24) & 0xFF;
    let red = (color >> 16) & 0xFF;
    let green = (color >> 8) & 0xFF;
    let blue = color & 0xFF;

    if alpha != 0xFF {
        return TestResult::Fail;
    }
    if red != 0x66 {
        return TestResult::Fail;
    }
    if green != 0xFF {
        return TestResult::Fail;
    }
    if blue != 0xFF {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_glow_colors_have_alpha() -> TestResult {
    let alpha_glow = (COLOR_ACCENT_GLOW >> 24) & 0xFF;
    let alpha_selection = (COLOR_SELECTION >> 24) & 0xFF;
    let alpha_glow_soft = (COLOR_GLOW_SOFT >> 24) & 0xFF;

    if !(alpha_glow < 0xFF) {
        return TestResult::Fail;
    }
    if !(alpha_selection < 0xFF) {
        return TestResult::Fail;
    }
    if !(alpha_glow_soft < 0xFF) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_opaque_colors_have_full_alpha() -> TestResult {
    if (COLOR_WHITE >> 24) & 0xFF != 0xFF {
        return TestResult::Fail;
    }
    if (COLOR_BLACK >> 24) & 0xFF != 0xFF {
        return TestResult::Fail;
    }
    if (COLOR_RED >> 24) & 0xFF != 0xFF {
        return TestResult::Fail;
    }
    if (COLOR_GREEN >> 24) & 0xFF != 0xFF {
        return TestResult::Fail;
    }
    if (COLOR_BLUE >> 24) & 0xFF != 0xFF {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_semantic_color_consistency() -> TestResult {
    if COLOR_SUCCESS != COLOR_GREEN {
        return TestResult::Fail;
    }
    if COLOR_ERROR != COLOR_RED {
        return TestResult::Fail;
    }
    if COLOR_INFO != COLOR_ACCENT {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_black_white_contrast() -> TestResult {
    if COLOR_BLACK == COLOR_WHITE {
        return TestResult::Fail;
    }
    if COLOR_BLACK != 0xFF000000 {
        return TestResult::Fail;
    }
    if COLOR_WHITE != 0xFFFFFFFF {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_background_is_dark() -> TestResult {
    let r = (COLOR_BG >> 16) & 0xFF;
    let g = (COLOR_BG >> 8) & 0xFF;
    let b = COLOR_BG & 0xFF;
    let brightness = (r + g + b) / 3;
    if !(brightness < 32) {
        return TestResult::Fail;
    }
    TestResult::Pass
}
