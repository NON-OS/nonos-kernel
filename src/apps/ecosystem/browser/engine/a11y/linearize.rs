extern crate alloc;
use super::types::{AccessibleNode, AriaRole};
use alloc::string::String;
use alloc::vec::Vec;

pub fn linearize(node: &AccessibleNode) -> Vec<String> {
    let mut output = Vec::new();
    linearize_recursive(node, &mut output);
    output
}

fn linearize_recursive(node: &AccessibleNode, output: &mut Vec<String>) {
    if node.state.hidden {
        return;
    }
    if node.role == AriaRole::Presentation || node.role == AriaRole::None {
        for child in &node.children {
            linearize_recursive(child, output);
        }
        return;
    }
    let announcement = format_announcement(node);
    if !announcement.is_empty() {
        output.push(announcement);
    }
    for child in &node.children {
        linearize_recursive(child, output);
    }
}

fn format_announcement(node: &AccessibleNode) -> String {
    let role_name = role_label(node.role);
    if node.name.is_empty() && role_name.is_empty() {
        return String::new();
    }
    if role_name.is_empty() {
        return node.name.clone();
    }
    if node.name.is_empty() {
        return String::from(role_name);
    }
    alloc::format!("{}, {}", node.name, role_name)
}

fn role_label(role: AriaRole) -> &'static str {
    match role {
        AriaRole::Button => "button",
        AriaRole::Link => "link",
        AriaRole::Heading => "heading",
        AriaRole::Navigation => "navigation",
        AriaRole::Main => "main",
        AriaRole::Banner => "banner",
        AriaRole::Form => "form",
        AriaRole::List => "list",
        AriaRole::ListItem => "list item",
        AriaRole::Img => "image",
        AriaRole::TextBox => "text field",
        AriaRole::Checkbox => "checkbox",
        AriaRole::Radio => "radio button",
        AriaRole::Dialog => "dialog",
        AriaRole::Alert => "alert",
        AriaRole::Status => "status",
        AriaRole::Tab => "tab",
        AriaRole::TabPanel => "tab panel",
        AriaRole::Table => "table",
        AriaRole::Region => "region",
        _ => "",
    }
}
