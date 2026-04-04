use crate::graphics::design_system::{borders, spacing, colors};

#[test]
fn test_border_radius_values() {
    assert_eq!(borders::RADIUS_NONE, 0);
    assert_eq!(borders::RADIUS_XS, 2);
    assert_eq!(borders::RADIUS_SM, 4);
    assert_eq!(borders::RADIUS_MD, 8);
    assert_eq!(borders::RADIUS_LG, 12);
    assert_eq!(borders::RADIUS_XL, 16);
    assert_eq!(borders::RADIUS_2XL, 24);
    assert_eq!(borders::RADIUS_FULL, 9999);
}

#[test]
fn test_border_component_radius() {
    assert_eq!(borders::RADIUS_WINDOW, borders::RADIUS_LG);
    assert_eq!(borders::RADIUS_BUTTON, borders::RADIUS_MD);
    assert_eq!(borders::RADIUS_INPUT, borders::RADIUS_MD);
    assert_eq!(borders::RADIUS_CARD, borders::RADIUS_LG);
    assert_eq!(borders::RADIUS_DIALOG, borders::RADIUS_XL);
    assert_eq!(borders::RADIUS_TOOLTIP, borders::RADIUS_SM);
    assert_eq!(borders::RADIUS_BADGE, borders::RADIUS_SM);
    assert_eq!(borders::RADIUS_DOCK, borders::RADIUS_XL);
    assert_eq!(borders::RADIUS_MENU, borders::RADIUS_MD);
    assert_eq!(borders::RADIUS_SCROLLBAR, borders::RADIUS_SM);
}

#[test]
fn test_border_width_values() {
    assert_eq!(borders::BORDER_NONE, 0);
    assert_eq!(borders::BORDER_THIN, 1);
    assert_eq!(borders::BORDER_NORMAL, 2);
    assert_eq!(borders::BORDER_THICK, 3);
    assert_eq!(borders::BORDER_FOCUS_WIDTH, 2);
}

#[test]
fn test_clamp_radius_no_clamp() {
    assert_eq!(borders::clamp_radius(8, 100, 100), 8);
    assert_eq!(borders::clamp_radius(10, 50, 100), 10);
}

#[test]
fn test_clamp_radius_clamps_to_width() {
    assert_eq!(borders::clamp_radius(100, 40, 100), 20);
}

#[test]
fn test_clamp_radius_clamps_to_height() {
    assert_eq!(borders::clamp_radius(100, 100, 40), 20);
}

#[test]
fn test_clamp_radius_at_limit() {
    assert_eq!(borders::clamp_radius(25, 50, 100), 25);
}

#[test]
fn test_is_pill_true() {
    assert!(borders::is_pill(50, 100, 100));
    assert!(borders::is_pill(25, 50, 100));
    assert!(borders::is_pill(100, 50, 100));
}

#[test]
fn test_is_pill_false() {
    assert!(!borders::is_pill(10, 100, 100));
    assert!(!borders::is_pill(5, 50, 100));
}

#[test]
fn test_is_pill_boundary() {
    assert!(!borders::is_pill(24, 50, 100));
    assert!(borders::is_pill(25, 50, 100));
}

#[test]
fn test_spacing_unit() {
    assert_eq!(spacing::scale::SPACE_UNIT, 4);
}

#[test]
fn test_spacing_scale() {
    assert_eq!(spacing::scale::SPACE_0, 0);
    assert_eq!(spacing::scale::SPACE_1, 4);
    assert_eq!(spacing::scale::SPACE_2, 8);
    assert_eq!(spacing::scale::SPACE_3, 12);
    assert_eq!(spacing::scale::SPACE_4, 16);
    assert_eq!(spacing::scale::SPACE_5, 20);
    assert_eq!(spacing::scale::SPACE_6, 24);
    assert_eq!(spacing::scale::SPACE_8, 32);
    assert_eq!(spacing::scale::SPACE_10, 40);
    assert_eq!(spacing::scale::SPACE_12, 48);
    assert_eq!(spacing::scale::SPACE_16, 64);
}

#[test]
fn test_spacing_scale_multiples() {
    assert_eq!(spacing::scale::SPACE_1, spacing::scale::SPACE_UNIT * 1);
    assert_eq!(spacing::scale::SPACE_2, spacing::scale::SPACE_UNIT * 2);
    assert_eq!(spacing::scale::SPACE_4, spacing::scale::SPACE_UNIT * 4);
    assert_eq!(spacing::scale::SPACE_8, spacing::scale::SPACE_UNIT * 8);
}

#[test]
fn test_semantic_accent_color() {
    assert_eq!(colors::semantic::ACCENT, 0xFF00D4FF);
    assert_eq!(colors::semantic::ACCENT_HOVER, 0xFF40E0FF);
    assert_eq!(colors::semantic::ACCENT_DIM, 0xFF007090);
    assert_eq!(colors::semantic::ACCENT_GLOW, 0xFF60E8FF);
}

#[test]
fn test_semantic_success_color() {
    assert_eq!(colors::semantic::SUCCESS, 0xFF22C55E);
    assert_eq!(colors::semantic::SUCCESS_GLOW, 0xFF4ADE80);
}

#[test]
fn test_semantic_warning_color() {
    assert_eq!(colors::semantic::WARNING, 0xFFF59E0B);
    assert_eq!(colors::semantic::WARNING_GLOW, 0xFFFBBF24);
}

#[test]
fn test_semantic_error_color() {
    assert_eq!(colors::semantic::ERROR, 0xFFEF4444);
    assert_eq!(colors::semantic::ERROR_GLOW, 0xFFF87171);
}

#[test]
fn test_semantic_info_color() {
    assert_eq!(colors::semantic::INFO, 0xFF3B82F6);
    assert_eq!(colors::semantic::INFO_GLOW, 0xFF60A5FA);
}

#[test]
fn test_semantic_other_colors() {
    assert_eq!(colors::semantic::PURPLE, 0xFFA855F7);
    assert_eq!(colors::semantic::PURPLE_GLOW, 0xFFC084FC);
    assert_eq!(colors::semantic::PINK, 0xFFEC4899);
    assert_eq!(colors::semantic::CYAN, 0xFF06B6D4);
}

#[test]
fn test_border_radius_hierarchy() {
    assert!(borders::RADIUS_XS < borders::RADIUS_SM);
    assert!(borders::RADIUS_SM < borders::RADIUS_MD);
    assert!(borders::RADIUS_MD < borders::RADIUS_LG);
    assert!(borders::RADIUS_LG < borders::RADIUS_XL);
    assert!(borders::RADIUS_XL < borders::RADIUS_2XL);
    assert!(borders::RADIUS_2XL < borders::RADIUS_FULL);
}

#[test]
fn test_border_width_hierarchy() {
    assert!(borders::BORDER_NONE < borders::BORDER_THIN);
    assert!(borders::BORDER_THIN < borders::BORDER_NORMAL);
    assert!(borders::BORDER_NORMAL < borders::BORDER_THICK);
}

#[test]
fn test_spacing_hierarchy() {
    assert!(spacing::scale::SPACE_0 < spacing::scale::SPACE_1);
    assert!(spacing::scale::SPACE_1 < spacing::scale::SPACE_2);
    assert!(spacing::scale::SPACE_2 < spacing::scale::SPACE_3);
    assert!(spacing::scale::SPACE_3 < spacing::scale::SPACE_4);
    assert!(spacing::scale::SPACE_4 < spacing::scale::SPACE_5);
    assert!(spacing::scale::SPACE_5 < spacing::scale::SPACE_6);
    assert!(spacing::scale::SPACE_6 < spacing::scale::SPACE_8);
    assert!(spacing::scale::SPACE_8 < spacing::scale::SPACE_10);
    assert!(spacing::scale::SPACE_10 < spacing::scale::SPACE_12);
    assert!(spacing::scale::SPACE_12 < spacing::scale::SPACE_16);
}

#[test]
fn test_semantic_colors_opaque() {
    assert_eq!((colors::semantic::ACCENT >> 24) & 0xFF, 0xFF);
    assert_eq!((colors::semantic::SUCCESS >> 24) & 0xFF, 0xFF);
    assert_eq!((colors::semantic::WARNING >> 24) & 0xFF, 0xFF);
    assert_eq!((colors::semantic::ERROR >> 24) & 0xFF, 0xFF);
    assert_eq!((colors::semantic::INFO >> 24) & 0xFF, 0xFF);
}
