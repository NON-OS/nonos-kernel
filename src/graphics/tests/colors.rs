use crate::graphics::framebuffer::colors::*;

#[test]
fn test_brand_accent_colors() {
    assert_eq!(COLOR_ACCENT, 0xFF66FFFF);
    assert_eq!(COLOR_ACCENT_DIM, 0xFF4DCCCC);
    assert_eq!(COLOR_ACCENT_GLOW, 0x4066FFFF);
}

#[test]
fn test_brand_secondary_colors() {
    assert_eq!(COLOR_SECONDARY, 0xFF2E5C5C);
    assert_eq!(COLOR_SECONDARY_DIM, 0xFF1E4040);
}

#[test]
fn test_background_colors() {
    assert_eq!(COLOR_BG, 0xFF080C10);
    assert_eq!(COLOR_BG_GRADIENT_TOP, 0xFF0A1014);
    assert_eq!(COLOR_BG_GRADIENT_BOTTOM, 0xFF050808);
}

#[test]
fn test_panel_colors() {
    assert_eq!(COLOR_PANEL, 0xFF0E1418);
    assert_eq!(COLOR_PANEL_HOVER, 0xFF141C22);
    assert_eq!(COLOR_PANEL_ACTIVE, 0xFF0A0E12);
    assert_eq!(COLOR_PANEL_BORDER, 0xFF1A2428);
}

#[test]
fn test_text_colors() {
    assert_eq!(COLOR_TEXT, 0xFF66FFFF);
    assert_eq!(COLOR_TEXT_WHITE, 0xFFF0F6FC);
    assert_eq!(COLOR_TEXT_DIM, 0xFF6E8088);
    assert_eq!(COLOR_TEXT_MUTED, 0xFF3A4448);
}

#[test]
fn test_terminal_colors() {
    assert_eq!(COLOR_TERMINAL_BG, 0xFF0A0E12);
    assert_eq!(COLOR_TERMINAL_BORDER, 0xFF1A2428);
}

#[test]
fn test_semantic_colors() {
    assert_eq!(COLOR_GREEN, 0xFF00E676);
    assert_eq!(COLOR_RED, 0xFFFF5252);
    assert_eq!(COLOR_YELLOW, 0xFFFFD740);
    assert_eq!(COLOR_ORANGE, 0xFFFF9100);
    assert_eq!(COLOR_PURPLE, 0xFFBB86FC);
}

#[test]
fn test_ui_state_colors() {
    assert_eq!(COLOR_SUCCESS, 0xFF00E676);
    assert_eq!(COLOR_ERROR, 0xFFFF5252);
    assert_eq!(COLOR_WARNING, 0xFFFFD740);
    assert_eq!(COLOR_INFO, 0xFF66FFFF);
}

#[test]
fn test_cursor_colors() {
    assert_eq!(COLOR_CURSOR, 0xFF66FFFF);
    assert_eq!(COLOR_SELECTION, 0x4066FFFF);
}

#[test]
fn test_grid_colors() {
    assert_eq!(COLOR_GRID, 0xFF0C1014);
    assert_eq!(COLOR_GRID_ACCENT, 0xFF101820);
    assert_eq!(COLOR_GLOW_SOFT, 0x1866FFFF);
}

#[test]
fn test_legacy_aliases() {
    assert_eq!(COLOR_FG, COLOR_TEXT);
    assert_eq!(COLOR_WHITE, 0xFFFFFFFF);
    assert_eq!(COLOR_BLACK, 0xFF000000);
    assert_eq!(COLOR_BLUE, COLOR_ACCENT);
    assert_eq!(COLOR_GRAY, 0xFF707070);
    assert_eq!(COLOR_DARK_GRAY, 0xFF383838);
    assert_eq!(COLOR_LIGHT_GRAY, 0xFFB0B0B0);
}

#[test]
fn test_menu_aliases() {
    assert_eq!(COLOR_MENU_BG, COLOR_PANEL);
    assert_eq!(COLOR_DOCK_BG, COLOR_PANEL);
    assert_eq!(COLOR_WINDOW_BG, COLOR_PANEL);
}

#[test]
fn test_title_aliases() {
    assert_eq!(COLOR_TITLE_BG, COLOR_PANEL_ACTIVE);
    assert_eq!(COLOR_TITLE_FG, COLOR_TEXT_WHITE);
}

#[test]
fn test_color_format_argb() {
    let color = COLOR_ACCENT;
    let alpha = (color >> 24) & 0xFF;
    let red = (color >> 16) & 0xFF;
    let green = (color >> 8) & 0xFF;
    let blue = color & 0xFF;

    assert_eq!(alpha, 0xFF);
    assert_eq!(red, 0x66);
    assert_eq!(green, 0xFF);
    assert_eq!(blue, 0xFF);
}

#[test]
fn test_glow_colors_have_alpha() {
    let alpha_glow = (COLOR_ACCENT_GLOW >> 24) & 0xFF;
    let alpha_selection = (COLOR_SELECTION >> 24) & 0xFF;
    let alpha_glow_soft = (COLOR_GLOW_SOFT >> 24) & 0xFF;

    assert!(alpha_glow < 0xFF);
    assert!(alpha_selection < 0xFF);
    assert!(alpha_glow_soft < 0xFF);
}

#[test]
fn test_opaque_colors_have_full_alpha() {
    assert_eq!((COLOR_WHITE >> 24) & 0xFF, 0xFF);
    assert_eq!((COLOR_BLACK >> 24) & 0xFF, 0xFF);
    assert_eq!((COLOR_RED >> 24) & 0xFF, 0xFF);
    assert_eq!((COLOR_GREEN >> 24) & 0xFF, 0xFF);
    assert_eq!((COLOR_BLUE >> 24) & 0xFF, 0xFF);
}

#[test]
fn test_semantic_color_consistency() {
    assert_eq!(COLOR_SUCCESS, COLOR_GREEN);
    assert_eq!(COLOR_ERROR, COLOR_RED);
    assert_eq!(COLOR_INFO, COLOR_ACCENT);
}

#[test]
fn test_black_white_contrast() {
    assert_ne!(COLOR_BLACK, COLOR_WHITE);
    assert_eq!(COLOR_BLACK, 0xFF000000);
    assert_eq!(COLOR_WHITE, 0xFFFFFFFF);
}

#[test]
fn test_background_is_dark() {
    let r = (COLOR_BG >> 16) & 0xFF;
    let g = (COLOR_BG >> 8) & 0xFF;
    let b = COLOR_BG & 0xFF;
    let brightness = (r + g + b) / 3;
    assert!(brightness < 32);
}
