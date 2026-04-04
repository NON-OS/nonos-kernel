use crate::graphics::window::ecosystem::*;

#[test]
fn test_ecosystem_tab_values() {
    assert_eq!(EcosystemTab::Browser as u8, 0);
    assert_eq!(EcosystemTab::Wallet as u8, 1);
    assert_eq!(EcosystemTab::Staking as u8, 2);
    assert_eq!(EcosystemTab::Liquidity as u8, 3);
    assert_eq!(EcosystemTab::Node as u8, 4);
    assert_eq!(EcosystemTab::Privacy as u8, 5);
}

#[test]
fn test_ecosystem_tab_from_u8() {
    assert_eq!(EcosystemTab::from_u8(0), EcosystemTab::Browser);
    assert_eq!(EcosystemTab::from_u8(1), EcosystemTab::Wallet);
    assert_eq!(EcosystemTab::from_u8(2), EcosystemTab::Staking);
    assert_eq!(EcosystemTab::from_u8(3), EcosystemTab::Liquidity);
    assert_eq!(EcosystemTab::from_u8(4), EcosystemTab::Node);
    assert_eq!(EcosystemTab::from_u8(5), EcosystemTab::Privacy);
}

#[test]
fn test_ecosystem_tab_from_u8_invalid() {
    assert_eq!(EcosystemTab::from_u8(6), EcosystemTab::Browser);
    assert_eq!(EcosystemTab::from_u8(100), EcosystemTab::Browser);
    assert_eq!(EcosystemTab::from_u8(255), EcosystemTab::Browser);
}

#[test]
fn test_ecosystem_tab_label() {
    assert_eq!(EcosystemTab::Browser.label(), b"Browser");
    assert_eq!(EcosystemTab::Wallet.label(), b"Wallet");
    assert_eq!(EcosystemTab::Staking.label(), b"Staking");
    assert_eq!(EcosystemTab::Liquidity.label(), b"LP");
    assert_eq!(EcosystemTab::Node.label(), b"Node");
    assert_eq!(EcosystemTab::Privacy.label(), b"Privacy");
}

#[test]
fn test_ecosystem_tab_count() {
    assert_eq!(EcosystemTab::count(), 6);
}

#[test]
fn test_ecosystem_tab_equality() {
    assert_eq!(EcosystemTab::Browser, EcosystemTab::Browser);
    assert_eq!(EcosystemTab::Wallet, EcosystemTab::Wallet);
    assert_ne!(EcosystemTab::Browser, EcosystemTab::Wallet);
    assert_ne!(EcosystemTab::Staking, EcosystemTab::Privacy);
}

#[test]
fn test_ecosystem_tab_copy() {
    let tab1 = EcosystemTab::Node;
    let tab2 = tab1;
    assert_eq!(tab1, tab2);
}

#[test]
fn test_ecosystem_tab_roundtrip() {
    for i in 0..EcosystemTab::count() {
        let tab = EcosystemTab::from_u8(i as u8);
        assert_eq!(tab as u8, i as u8);
    }
}

#[test]
fn test_tab_labels_not_empty() {
    for i in 0..EcosystemTab::count() {
        let tab = EcosystemTab::from_u8(i as u8);
        assert!(!tab.label().is_empty());
    }
}

#[test]
fn test_ecosystem_tab_default() {
    let default_tab = EcosystemTab::from_u8(0);
    assert_eq!(default_tab, EcosystemTab::Browser);
}

#[test]
fn test_get_set_active_tab() {
    let original = get_active_tab();

    set_active_tab(EcosystemTab::Wallet);
    assert_eq!(get_active_tab(), EcosystemTab::Wallet);

    set_active_tab(EcosystemTab::Staking);
    assert_eq!(get_active_tab(), EcosystemTab::Staking);

    set_active_tab(EcosystemTab::Privacy);
    assert_eq!(get_active_tab(), EcosystemTab::Privacy);

    set_active_tab(original);
}

#[test]
fn test_set_all_tabs() {
    let original = get_active_tab();

    let tabs = [
        EcosystemTab::Browser,
        EcosystemTab::Wallet,
        EcosystemTab::Staking,
        EcosystemTab::Liquidity,
        EcosystemTab::Node,
        EcosystemTab::Privacy,
    ];

    for tab in tabs {
        set_active_tab(tab);
        assert_eq!(get_active_tab(), tab);
    }

    set_active_tab(original);
}

#[test]
fn test_input_focused_query() {
    let _focused = is_input_focused();
}

#[test]
fn test_tab_constants() {
    use crate::graphics::window::ecosystem::tabs::*;

    assert_eq!(TAB_HEIGHT, 40);
    assert_eq!(TAB_MIN_WIDTH, 80);
    assert_eq!(TAB_PADDING, 16);
}

#[test]
fn test_tab_colors() {
    use crate::graphics::window::ecosystem::tabs::*;

    assert_eq!(COLOR_TAB_BAR, 0xFF1C1C1E);
    assert_eq!(COLOR_TAB_ACTIVE, 0xFF007AFF);
    assert_eq!(COLOR_TAB_HOVER, 0xFF2C2C2E);
    assert_eq!(COLOR_TAB_TEXT, 0xFF8E8E93);
    assert_eq!(COLOR_TAB_TEXT_ACTIVE, 0xFFFFFFFF);
    assert_eq!(COLOR_TAB_BORDER, 0xFF38383A);
}

#[test]
fn test_tab_layout_calculation() {
    use crate::graphics::window::ecosystem::tabs::*;

    let layout = calculate_layout(800);
    assert_eq!(layout.tabs.len(), 6);

    for i in 0..EcosystemTab::count() {
        let (x, w, h) = layout.tabs[i];
        assert!(w >= 40);
        assert_eq!(h, TAB_HEIGHT);
        if i > 0 {
            let (prev_x, prev_w, _) = layout.tabs[i - 1];
            assert!(x >= prev_x + prev_w);
        }
    }
}

#[test]
fn test_tab_layout_narrow_width() {
    use crate::graphics::window::ecosystem::tabs::*;

    let layout = calculate_layout(300);
    for i in 0..EcosystemTab::count() {
        let (_, w, _) = layout.tabs[i];
        assert!(w >= 40);
    }
}

#[test]
fn test_tab_layout_wide_width() {
    use crate::graphics::window::ecosystem::tabs::*;

    let layout = calculate_layout(1200);
    assert!(layout.total_width <= 1200);
}
