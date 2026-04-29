use crate::graphics::window::ecosystem::*;
use crate::test::framework::TestResult;

pub(crate) fn test_ecosystem_tab_values() -> TestResult {
    if EcosystemTab::Browser as u8 != 0 {
        return TestResult::Fail;
    }
    if EcosystemTab::Wallet as u8 != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ecosystem_tab_from_u8() -> TestResult {
    if EcosystemTab::from_u8(0) != EcosystemTab::Browser {
        return TestResult::Fail;
    }
    if EcosystemTab::from_u8(1) != EcosystemTab::Wallet {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ecosystem_tab_from_u8_invalid() -> TestResult {
    if EcosystemTab::from_u8(2) != EcosystemTab::Browser {
        return TestResult::Fail;
    }
    if EcosystemTab::from_u8(100) != EcosystemTab::Browser {
        return TestResult::Fail;
    }
    if EcosystemTab::from_u8(255) != EcosystemTab::Browser {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ecosystem_tab_label() -> TestResult {
    if EcosystemTab::Browser.label() != b"Browser" {
        return TestResult::Fail;
    }
    if EcosystemTab::Wallet.label() != b"Wallet" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ecosystem_tab_count() -> TestResult {
    if EcosystemTab::count() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ecosystem_tab_equality() -> TestResult {
    if EcosystemTab::Browser != EcosystemTab::Browser {
        return TestResult::Fail;
    }
    if EcosystemTab::Wallet != EcosystemTab::Wallet {
        return TestResult::Fail;
    }
    if EcosystemTab::Browser == EcosystemTab::Wallet {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ecosystem_tab_copy() -> TestResult {
    let tab1 = EcosystemTab::Wallet;
    let tab2 = tab1;
    if tab1 != tab2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_ecosystem_tab_roundtrip() -> TestResult {
    for i in 0..EcosystemTab::count() {
        let tab = EcosystemTab::from_u8(i as u8);
        if tab as u8 != i as u8 {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_tab_labels_not_empty() -> TestResult {
    for i in 0..EcosystemTab::count() {
        let tab = EcosystemTab::from_u8(i as u8);
        if tab.label().is_empty() {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_ecosystem_tab_default() -> TestResult {
    let default_tab = EcosystemTab::from_u8(0);
    if default_tab != EcosystemTab::Browser {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_set_active_tab() -> TestResult {
    let original = get_active_tab();
    set_active_tab(EcosystemTab::Wallet);
    if get_active_tab() != EcosystemTab::Wallet {
        return TestResult::Fail;
    }
    set_active_tab(EcosystemTab::Browser);
    if get_active_tab() != EcosystemTab::Browser {
        return TestResult::Fail;
    }
    set_active_tab(original);
    TestResult::Pass
}

pub(crate) fn test_set_all_tabs() -> TestResult {
    let original = get_active_tab();
    let tabs = [EcosystemTab::Browser, EcosystemTab::Wallet];
    for tab in tabs {
        set_active_tab(tab);
        if get_active_tab() != tab {
            return TestResult::Fail;
        }
    }
    set_active_tab(original);
    TestResult::Pass
}

pub(crate) fn test_input_focused_query() -> TestResult {
    let _focused = is_input_focused();
    TestResult::Pass
}

pub(crate) fn test_tab_constants() -> TestResult {
    use crate::graphics::window::ecosystem::tabs::*;
    if TAB_HEIGHT != 40 {
        return TestResult::Fail;
    }
    if TAB_MIN_WIDTH != 80 {
        return TestResult::Fail;
    }
    if TAB_PADDING != 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tab_colors() -> TestResult {
    use crate::graphics::window::ecosystem::tabs::*;
    if COLOR_TAB_BAR != 0xFF1C1C1E {
        return TestResult::Fail;
    }
    if COLOR_TAB_ACTIVE != 0xFF007AFF {
        return TestResult::Fail;
    }
    if COLOR_TAB_HOVER != 0xFF2C2C2E {
        return TestResult::Fail;
    }
    if COLOR_TAB_TEXT != 0xFF8E8E93 {
        return TestResult::Fail;
    }
    if COLOR_TAB_TEXT_ACTIVE != 0xFFFFFFFF {
        return TestResult::Fail;
    }
    if COLOR_TAB_BORDER != 0xFF38383A {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_tab_layout_calculation() -> TestResult {
    use crate::graphics::window::ecosystem::tabs::*;
    let layout = calculate_layout(800);
    if layout.tabs.len() != 2 {
        return TestResult::Fail;
    }
    for i in 0..EcosystemTab::count() {
        let (x, w, h) = layout.tabs[i];
        if !(w >= 40) {
            return TestResult::Fail;
        }
        if h != TAB_HEIGHT {
            return TestResult::Fail;
        }
        if i > 0 {
            let (prev_x, prev_w, _) = layout.tabs[i - 1];
            if !(x >= prev_x + prev_w) {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_tab_layout_narrow_width() -> TestResult {
    use crate::graphics::window::ecosystem::tabs::*;
    let layout = calculate_layout(300);
    for i in 0..EcosystemTab::count() {
        let (_, w, _) = layout.tabs[i];
        if !(w >= 40) {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_tab_layout_wide_width() -> TestResult {
    use crate::graphics::window::ecosystem::tabs::*;
    let layout = calculate_layout(1200);
    if !(layout.total_width <= 1200) {
        return TestResult::Fail;
    }
    TestResult::Pass
}
