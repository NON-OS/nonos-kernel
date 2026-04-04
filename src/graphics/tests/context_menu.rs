use crate::graphics::window::context_menu::types::*;

#[test]
fn test_menu_item_type_values() {
    assert_eq!(MenuItemType::Action, MenuItemType::Action);
    assert_eq!(MenuItemType::Separator, MenuItemType::Separator);
    assert_eq!(MenuItemType::Disabled, MenuItemType::Disabled);
}

#[test]
fn test_menu_item_type_inequality() {
    assert_ne!(MenuItemType::Action, MenuItemType::Separator);
    assert_ne!(MenuItemType::Action, MenuItemType::Disabled);
    assert_ne!(MenuItemType::Separator, MenuItemType::Disabled);
}

#[test]
fn test_menu_item_action() {
    let item = MenuItem::action(b"Open", 1);
    assert_eq!(item.label, b"Open");
    assert_eq!(item.item_type, MenuItemType::Action);
    assert_eq!(item.action_id, 1);
}

#[test]
fn test_menu_item_separator() {
    let item = MenuItem::separator();
    assert_eq!(item.label, b"");
    assert_eq!(item.item_type, MenuItemType::Separator);
    assert_eq!(item.action_id, 0);
}

#[test]
fn test_menu_item_disabled() {
    let item = MenuItem::disabled(b"Cannot Edit");
    assert_eq!(item.label, b"Cannot Edit");
    assert_eq!(item.item_type, MenuItemType::Disabled);
    assert_eq!(item.action_id, 0);
}

#[test]
fn test_context_menu_type_values() {
    assert_eq!(ContextMenuType::None as u8, 0);
    assert_eq!(ContextMenuType::Desktop as u8, 1);
    assert_eq!(ContextMenuType::FileManager as u8, 2);
    assert_eq!(ContextMenuType::TextEditor as u8, 3);
    assert_eq!(ContextMenuType::Window as u8, 4);
}

#[test]
fn test_context_menu_type_equality() {
    assert_eq!(ContextMenuType::None, ContextMenuType::None);
    assert_eq!(ContextMenuType::Desktop, ContextMenuType::Desktop);
    assert_eq!(ContextMenuType::FileManager, ContextMenuType::FileManager);
    assert_eq!(ContextMenuType::TextEditor, ContextMenuType::TextEditor);
    assert_eq!(ContextMenuType::Window, ContextMenuType::Window);
}

#[test]
fn test_context_menu_type_inequality() {
    assert_ne!(ContextMenuType::None, ContextMenuType::Desktop);
    assert_ne!(ContextMenuType::Desktop, ContextMenuType::FileManager);
    assert_ne!(ContextMenuType::FileManager, ContextMenuType::TextEditor);
    assert_ne!(ContextMenuType::TextEditor, ContextMenuType::Window);
}

#[test]
fn test_context_menu_type_copy() {
    let t1 = ContextMenuType::Desktop;
    let t2 = t1;
    assert_eq!(t1, t2);
}

#[test]
fn test_menu_item_type_copy() {
    let t1 = MenuItemType::Action;
    let t2 = t1;
    assert_eq!(t1, t2);
}

#[test]
fn test_menu_item_copy() {
    let item = MenuItem::action(b"Copy", 5);
    let copied = item;
    assert_eq!(copied.label, b"Copy");
    assert_eq!(copied.action_id, 5);
}

#[test]
fn test_menu_item_const_action() {
    const ITEM: MenuItem = MenuItem::action(b"Test", 99);
    assert_eq!(ITEM.label, b"Test");
    assert_eq!(ITEM.action_id, 99);
}

#[test]
fn test_menu_item_const_separator() {
    const SEP: MenuItem = MenuItem::separator();
    assert_eq!(SEP.item_type, MenuItemType::Separator);
}

#[test]
fn test_menu_item_const_disabled() {
    const DIS: MenuItem = MenuItem::disabled(b"Disabled");
    assert_eq!(DIS.item_type, MenuItemType::Disabled);
}

#[test]
fn test_menu_items_array() {
    let items = [
        MenuItem::action(b"Cut", 1),
        MenuItem::action(b"Copy", 2),
        MenuItem::action(b"Paste", 3),
        MenuItem::separator(),
        MenuItem::action(b"Delete", 4),
        MenuItem::separator(),
        MenuItem::disabled(b"Properties"),
    ];

    assert_eq!(items.len(), 7);
    assert_eq!(items[0].action_id, 1);
    assert_eq!(items[1].action_id, 2);
    assert_eq!(items[2].action_id, 3);
    assert_eq!(items[3].item_type, MenuItemType::Separator);
    assert_eq!(items[4].action_id, 4);
    assert_eq!(items[5].item_type, MenuItemType::Separator);
    assert_eq!(items[6].item_type, MenuItemType::Disabled);
}

#[test]
fn test_action_ids_unique() {
    let items = [
        MenuItem::action(b"A", 1),
        MenuItem::action(b"B", 2),
        MenuItem::action(b"C", 3),
    ];

    for i in 0..items.len() {
        for j in (i + 1)..items.len() {
            assert_ne!(items[i].action_id, items[j].action_id);
        }
    }
}

#[test]
fn test_menu_item_empty_label() {
    let item = MenuItem::action(b"", 0);
    assert_eq!(item.label, b"");
    assert_eq!(item.item_type, MenuItemType::Action);
}

#[test]
fn test_menu_item_long_label() {
    let long_label = b"This is a very long menu item label for testing";
    let item = MenuItem::action(long_label, 10);
    assert_eq!(item.label, long_label);
}
