use crate::graphics::themes::*;

#[test]
fn test_theme_values() {
    assert_eq!(Theme::NonosDark as u8, 0);
    assert_eq!(Theme::GitHubDark as u8, 1);
    assert_eq!(Theme::SolarizedDark as u8, 2);
    assert_eq!(Theme::DeepPurple as u8, 3);
    assert_eq!(Theme::OceanBlue as u8, 4);
    assert_eq!(Theme::ForestGreen as u8, 5);
}

#[test]
fn test_theme_from_u8() {
    assert_eq!(Theme::from_u8(0), Theme::NonosDark);
    assert_eq!(Theme::from_u8(1), Theme::GitHubDark);
    assert_eq!(Theme::from_u8(2), Theme::SolarizedDark);
    assert_eq!(Theme::from_u8(3), Theme::DeepPurple);
    assert_eq!(Theme::from_u8(4), Theme::OceanBlue);
    assert_eq!(Theme::from_u8(5), Theme::ForestGreen);
}

#[test]
fn test_theme_from_u8_invalid() {
    assert_eq!(Theme::from_u8(6), Theme::NonosDark);
    assert_eq!(Theme::from_u8(100), Theme::NonosDark);
    assert_eq!(Theme::from_u8(255), Theme::NonosDark);
}

#[test]
fn test_theme_count() {
    assert_eq!(Theme::count(), 6);
}

#[test]
fn test_theme_name() {
    assert_eq!(Theme::NonosDark.name(), "NONOS Dark");
    assert_eq!(Theme::GitHubDark.name(), "GitHub Dark");
    assert_eq!(Theme::SolarizedDark.name(), "Solarized Dark");
    assert_eq!(Theme::DeepPurple.name(), "Deep Purple");
    assert_eq!(Theme::OceanBlue.name(), "Ocean Blue");
    assert_eq!(Theme::ForestGreen.name(), "Forest Green");
}

#[test]
fn test_theme_next() {
    assert_eq!(Theme::NonosDark.next(), Theme::GitHubDark);
    assert_eq!(Theme::GitHubDark.next(), Theme::SolarizedDark);
    assert_eq!(Theme::SolarizedDark.next(), Theme::DeepPurple);
    assert_eq!(Theme::DeepPurple.next(), Theme::OceanBlue);
    assert_eq!(Theme::OceanBlue.next(), Theme::ForestGreen);
    assert_eq!(Theme::ForestGreen.next(), Theme::NonosDark);
}

#[test]
fn test_theme_prev() {
    assert_eq!(Theme::NonosDark.prev(), Theme::ForestGreen);
    assert_eq!(Theme::GitHubDark.prev(), Theme::NonosDark);
    assert_eq!(Theme::SolarizedDark.prev(), Theme::GitHubDark);
    assert_eq!(Theme::DeepPurple.prev(), Theme::SolarizedDark);
    assert_eq!(Theme::OceanBlue.prev(), Theme::DeepPurple);
    assert_eq!(Theme::ForestGreen.prev(), Theme::OceanBlue);
}

#[test]
fn test_theme_cycle_next_full() {
    let mut theme = Theme::NonosDark;
    for _ in 0..Theme::count() {
        theme = theme.next();
    }
    assert_eq!(theme, Theme::NonosDark);
}

#[test]
fn test_theme_cycle_prev_full() {
    let mut theme = Theme::NonosDark;
    for _ in 0..Theme::count() {
        theme = theme.prev();
    }
    assert_eq!(theme, Theme::NonosDark);
}

#[test]
fn test_color_scheme_nonos_dark() {
    let colors = Theme::NonosDark.colors();
    assert_eq!(colors.bg_primary, 0xFF0D1117);
    assert_eq!(colors.bg_secondary, 0xFF161B22);
    assert_eq!(colors.bg_tertiary, 0xFF21262D);
    assert_eq!(colors.text_primary, 0xFFFFFFFF);
    assert_eq!(colors.text_secondary, 0xFF7D8590);
    assert_eq!(colors.accent, 0xFF58A6FF);
    assert_eq!(colors.success, 0xFF3FB950);
    assert_eq!(colors.warning, 0xFFD29922);
    assert_eq!(colors.error, 0xFFF85149);
    assert_eq!(colors.border, 0xFF30363D);
}

#[test]
fn test_color_scheme_solarized() {
    let colors = Theme::SolarizedDark.colors();
    assert_eq!(colors.bg_primary, 0xFF002B36);
    assert_eq!(colors.accent, 0xFF268BD2);
    assert_eq!(colors.success, 0xFF859900);
    assert_eq!(colors.error, 0xFFDC322F);
}

#[test]
fn test_color_scheme_deep_purple() {
    let colors = Theme::DeepPurple.colors();
    assert_eq!(colors.bg_primary, 0xFF1A0A28);
    assert_eq!(colors.accent, 0xFFBB86FC);
    assert_eq!(colors.success, 0xFF03DAC5);
    assert_eq!(colors.error, 0xFFCF6679);
}

#[test]
fn test_color_scheme_ocean_blue() {
    let colors = Theme::OceanBlue.colors();
    assert_eq!(colors.bg_primary, 0xFF0A1A28);
    assert_eq!(colors.accent, 0xFF00B4D8);
    assert_eq!(colors.success, 0xFF40E0D0);
}

#[test]
fn test_color_scheme_forest_green() {
    let colors = Theme::ForestGreen.colors();
    assert_eq!(colors.bg_primary, 0xFF0A1A0F);
    assert_eq!(colors.accent, 0xFF4CAF50);
    assert_eq!(colors.success, 0xFF8BC34A);
}

#[test]
fn test_all_themes_have_valid_colors() {
    for i in 0..Theme::count() {
        let theme = Theme::from_u8(i);
        let colors = theme.colors();
        assert_ne!(colors.bg_primary, 0);
        assert_ne!(colors.text_primary, 0);
        assert_ne!(colors.accent, 0);
    }
}

#[test]
fn test_theme_equality() {
    assert_eq!(Theme::NonosDark, Theme::NonosDark);
    assert_ne!(Theme::NonosDark, Theme::GitHubDark);
    assert_ne!(Theme::SolarizedDark, Theme::OceanBlue);
}

#[test]
fn test_theme_copy() {
    let t1 = Theme::DeepPurple;
    let t2 = t1;
    assert_eq!(t1, t2);
}

#[test]
fn test_color_scheme_copy() {
    let c1 = Theme::NonosDark.colors();
    let c2 = c1;
    assert_eq!(c1.bg_primary, c2.bg_primary);
    assert_eq!(c1.accent, c2.accent);
}

#[test]
fn test_theme_roundtrip() {
    for i in 0..Theme::count() {
        let theme = Theme::from_u8(i);
        assert_eq!(theme as u8, i);
    }
}
