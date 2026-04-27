use crate::graphics::themes::*;
use crate::test::framework::TestResult;

pub(crate) fn test_theme_values() -> TestResult {
    if Theme::NonosDark as u8 != 0 {
        return TestResult::Fail;
    }
    if Theme::GitHubDark as u8 != 1 {
        return TestResult::Fail;
    }
    if Theme::SolarizedDark as u8 != 2 {
        return TestResult::Fail;
    }
    if Theme::DeepPurple as u8 != 3 {
        return TestResult::Fail;
    }
    if Theme::OceanBlue as u8 != 4 {
        return TestResult::Fail;
    }
    if Theme::ForestGreen as u8 != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_theme_from_u8() -> TestResult {
    if Theme::from_u8(0) != Theme::NonosDark {
        return TestResult::Fail;
    }
    if Theme::from_u8(1) != Theme::GitHubDark {
        return TestResult::Fail;
    }
    if Theme::from_u8(2) != Theme::SolarizedDark {
        return TestResult::Fail;
    }
    if Theme::from_u8(3) != Theme::DeepPurple {
        return TestResult::Fail;
    }
    if Theme::from_u8(4) != Theme::OceanBlue {
        return TestResult::Fail;
    }
    if Theme::from_u8(5) != Theme::ForestGreen {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_theme_from_u8_invalid() -> TestResult {
    if Theme::from_u8(6) != Theme::NonosDark {
        return TestResult::Fail;
    }
    if Theme::from_u8(100) != Theme::NonosDark {
        return TestResult::Fail;
    }
    if Theme::from_u8(255) != Theme::NonosDark {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_theme_count() -> TestResult {
    if Theme::count() != 6 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_theme_name() -> TestResult {
    if Theme::NonosDark.name() != "NONOS Dark" {
        return TestResult::Fail;
    }
    if Theme::GitHubDark.name() != "GitHub Dark" {
        return TestResult::Fail;
    }
    if Theme::SolarizedDark.name() != "Solarized Dark" {
        return TestResult::Fail;
    }
    if Theme::DeepPurple.name() != "Deep Purple" {
        return TestResult::Fail;
    }
    if Theme::OceanBlue.name() != "Ocean Blue" {
        return TestResult::Fail;
    }
    if Theme::ForestGreen.name() != "Forest Green" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_theme_next() -> TestResult {
    if Theme::NonosDark.next() != Theme::GitHubDark {
        return TestResult::Fail;
    }
    if Theme::GitHubDark.next() != Theme::SolarizedDark {
        return TestResult::Fail;
    }
    if Theme::SolarizedDark.next() != Theme::DeepPurple {
        return TestResult::Fail;
    }
    if Theme::DeepPurple.next() != Theme::OceanBlue {
        return TestResult::Fail;
    }
    if Theme::OceanBlue.next() != Theme::ForestGreen {
        return TestResult::Fail;
    }
    if Theme::ForestGreen.next() != Theme::NonosDark {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_theme_prev() -> TestResult {
    if Theme::NonosDark.prev() != Theme::ForestGreen {
        return TestResult::Fail;
    }
    if Theme::GitHubDark.prev() != Theme::NonosDark {
        return TestResult::Fail;
    }
    if Theme::SolarizedDark.prev() != Theme::GitHubDark {
        return TestResult::Fail;
    }
    if Theme::DeepPurple.prev() != Theme::SolarizedDark {
        return TestResult::Fail;
    }
    if Theme::OceanBlue.prev() != Theme::DeepPurple {
        return TestResult::Fail;
    }
    if Theme::ForestGreen.prev() != Theme::OceanBlue {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_theme_cycle_next_full() -> TestResult {
    let mut theme = Theme::NonosDark;
    for _ in 0..Theme::count() {
        theme = theme.next();
    }
    if theme != Theme::NonosDark {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_theme_cycle_prev_full() -> TestResult {
    let mut theme = Theme::NonosDark;
    for _ in 0..Theme::count() {
        theme = theme.prev();
    }
    if theme != Theme::NonosDark {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_color_scheme_nonos_dark() -> TestResult {
    let colors = Theme::NonosDark.colors();
    if colors.bg_primary != 0xFF0D1117 {
        return TestResult::Fail;
    }
    if colors.bg_secondary != 0xFF161B22 {
        return TestResult::Fail;
    }
    if colors.bg_tertiary != 0xFF21262D {
        return TestResult::Fail;
    }
    if colors.text_primary != 0xFFFFFFFF {
        return TestResult::Fail;
    }
    if colors.text_secondary != 0xFF7D8590 {
        return TestResult::Fail;
    }
    if colors.accent != 0xFF58A6FF {
        return TestResult::Fail;
    }
    if colors.success != 0xFF3FB950 {
        return TestResult::Fail;
    }
    if colors.warning != 0xFFD29922 {
        return TestResult::Fail;
    }
    if colors.error != 0xFFF85149 {
        return TestResult::Fail;
    }
    if colors.border != 0xFF30363D {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_color_scheme_solarized() -> TestResult {
    let colors = Theme::SolarizedDark.colors();
    if colors.bg_primary != 0xFF002B36 {
        return TestResult::Fail;
    }
    if colors.accent != 0xFF268BD2 {
        return TestResult::Fail;
    }
    if colors.success != 0xFF859900 {
        return TestResult::Fail;
    }
    if colors.error != 0xFFDC322F {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_color_scheme_deep_purple() -> TestResult {
    let colors = Theme::DeepPurple.colors();
    if colors.bg_primary != 0xFF1A0A28 {
        return TestResult::Fail;
    }
    if colors.accent != 0xFFBB86FC {
        return TestResult::Fail;
    }
    if colors.success != 0xFF03DAC5 {
        return TestResult::Fail;
    }
    if colors.error != 0xFFCF6679 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_color_scheme_ocean_blue() -> TestResult {
    let colors = Theme::OceanBlue.colors();
    if colors.bg_primary != 0xFF0A1A28 {
        return TestResult::Fail;
    }
    if colors.accent != 0xFF00B4D8 {
        return TestResult::Fail;
    }
    if colors.success != 0xFF40E0D0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_color_scheme_forest_green() -> TestResult {
    let colors = Theme::ForestGreen.colors();
    if colors.bg_primary != 0xFF0A1A0F {
        return TestResult::Fail;
    }
    if colors.accent != 0xFF4CAF50 {
        return TestResult::Fail;
    }
    if colors.success != 0xFF8BC34A {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_all_themes_have_valid_colors() -> TestResult {
    for i in 0..Theme::count() {
        let theme = Theme::from_u8(i);
        let colors = theme.colors();
        if colors.bg_primary == 0 {
            return TestResult::Fail;
        }
        if colors.text_primary == 0 {
            return TestResult::Fail;
        }
        if colors.accent == 0 {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_theme_equality() -> TestResult {
    if Theme::NonosDark != Theme::NonosDark {
        return TestResult::Fail;
    }
    if Theme::NonosDark == Theme::GitHubDark {
        return TestResult::Fail;
    }
    if Theme::SolarizedDark == Theme::OceanBlue {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_theme_copy() -> TestResult {
    let t1 = Theme::DeepPurple;
    let t2 = t1;
    if t1 != t2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_color_scheme_copy() -> TestResult {
    let c1 = Theme::NonosDark.colors();
    let c2 = c1;
    if c1.bg_primary != c2.bg_primary {
        return TestResult::Fail;
    }
    if c1.accent != c2.accent {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_theme_roundtrip() -> TestResult {
    for i in 0..Theme::count() {
        let theme = Theme::from_u8(i);
        if theme as u8 != i {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}
