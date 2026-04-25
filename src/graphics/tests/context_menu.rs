use crate::graphics::window::context_menu::types::*;
use crate::test::framework::TestResult;

pub(crate) fn test_menu_item_type_values() -> TestResult {
    if MenuItemType::Action != MenuItemType::Action {
        return TestResult::Fail;
    }
    if MenuItemType::Separator != MenuItemType::Separator {
        return TestResult::Fail;
    }
    if MenuItemType::Disabled != MenuItemType::Disabled {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_menu_item_type_inequality() -> TestResult {
    if MenuItemType::Action == MenuItemType::Separator {
        return TestResult::Fail;
    }
    if MenuItemType::Action == MenuItemType::Disabled {
        return TestResult::Fail;
    }
    if MenuItemType::Separator == MenuItemType::Disabled {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_menu_item_action() -> TestResult {
    let item = MenuItem::action(b"Open", 1);
    if item.label != b"Open" {
        return TestResult::Fail;
    }
    if item.item_type != MenuItemType::Action {
        return TestResult::Fail;
    }
    if item.action_id != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_menu_item_separator() -> TestResult {
    let item = MenuItem::separator();
    if item.label != b"" {
        return TestResult::Fail;
    }
    if item.item_type != MenuItemType::Separator {
        return TestResult::Fail;
    }
    if item.action_id != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_menu_item_disabled() -> TestResult {
    let item = MenuItem::disabled(b"Cannot Edit");
    if item.label != b"Cannot Edit" {
        return TestResult::Fail;
    }
    if item.item_type != MenuItemType::Disabled {
        return TestResult::Fail;
    }
    if item.action_id != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_context_menu_type_values() -> TestResult {
    if ContextMenuType::None as u8 != 0 {
        return TestResult::Fail;
    }
    if ContextMenuType::Desktop as u8 != 1 {
        return TestResult::Fail;
    }
    if ContextMenuType::FileManager as u8 != 2 {
        return TestResult::Fail;
    }
    if ContextMenuType::TextEditor as u8 != 3 {
        return TestResult::Fail;
    }
    if ContextMenuType::Window as u8 != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_context_menu_type_equality() -> TestResult {
    if ContextMenuType::None != ContextMenuType::None {
        return TestResult::Fail;
    }
    if ContextMenuType::Desktop != ContextMenuType::Desktop {
        return TestResult::Fail;
    }
    if ContextMenuType::FileManager != ContextMenuType::FileManager {
        return TestResult::Fail;
    }
    if ContextMenuType::TextEditor != ContextMenuType::TextEditor {
        return TestResult::Fail;
    }
    if ContextMenuType::Window != ContextMenuType::Window {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_context_menu_type_inequality() -> TestResult {
    if ContextMenuType::None == ContextMenuType::Desktop {
        return TestResult::Fail;
    }
    if ContextMenuType::Desktop == ContextMenuType::FileManager {
        return TestResult::Fail;
    }
    if ContextMenuType::FileManager == ContextMenuType::TextEditor {
        return TestResult::Fail;
    }
    if ContextMenuType::TextEditor == ContextMenuType::Window {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_context_menu_type_copy() -> TestResult {
    let t1 = ContextMenuType::Desktop;
    let t2 = t1;
    if t1 != t2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_menu_item_type_copy() -> TestResult {
    let t1 = MenuItemType::Action;
    let t2 = t1;
    if t1 != t2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_menu_item_copy() -> TestResult {
    let item = MenuItem::action(b"Copy", 5);
    let copied = item;
    if copied.label != b"Copy" {
        return TestResult::Fail;
    }
    if copied.action_id != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_menu_item_const_action() -> TestResult {
    const ITEM: MenuItem = MenuItem::action(b"Test", 99);
    if ITEM.label != b"Test" {
        return TestResult::Fail;
    }
    if ITEM.action_id != 99 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_menu_item_const_separator() -> TestResult {
    const SEP: MenuItem = MenuItem::separator();
    if SEP.item_type != MenuItemType::Separator {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_menu_item_const_disabled() -> TestResult {
    const DIS: MenuItem = MenuItem::disabled(b"Disabled");
    if DIS.item_type != MenuItemType::Disabled {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_menu_items_array() -> TestResult {
    let items = [
        MenuItem::action(b"Cut", 1),
        MenuItem::action(b"Copy", 2),
        MenuItem::action(b"Paste", 3),
        MenuItem::separator(),
        MenuItem::action(b"Delete", 4),
        MenuItem::separator(),
        MenuItem::disabled(b"Properties"),
    ];

    if items.len() != 7 {
        return TestResult::Fail;
    }
    if items[0].action_id != 1 {
        return TestResult::Fail;
    }
    if items[1].action_id != 2 {
        return TestResult::Fail;
    }
    if items[2].action_id != 3 {
        return TestResult::Fail;
    }
    if items[3].item_type != MenuItemType::Separator {
        return TestResult::Fail;
    }
    if items[4].action_id != 4 {
        return TestResult::Fail;
    }
    if items[5].item_type != MenuItemType::Separator {
        return TestResult::Fail;
    }
    if items[6].item_type != MenuItemType::Disabled {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_action_ids_unique() -> TestResult {
    let items = [MenuItem::action(b"A", 1), MenuItem::action(b"B", 2), MenuItem::action(b"C", 3)];

    for i in 0..items.len() {
        for j in (i + 1)..items.len() {
            if items[i].action_id == items[j].action_id {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_menu_item_empty_label() -> TestResult {
    let item = MenuItem::action(b"", 0);
    if item.label != b"" {
        return TestResult::Fail;
    }
    if item.item_type != MenuItemType::Action {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_menu_item_long_label() -> TestResult {
    let long_label = b"This is a very long menu item label for testing";
    let item = MenuItem::action(long_label, 10);
    if item.label != long_label {
        return TestResult::Fail;
    }
    TestResult::Pass
}
