extern crate alloc;
use alloc::string::String;
use super::super::types::AccessibleNode;

pub fn apply_aria_attrs(node: &mut AccessibleNode, attrs: &[(String, String)]) {
    for (key, value) in attrs {
        match key.as_str() {
            "aria-label" => node.name = value.clone(),
            "aria-describedby" => node.description = value.clone(),
            "aria-hidden" => node.state.hidden = value == "true",
            "aria-disabled" => node.state.disabled = value == "true",
            "aria-checked" => node.state.checked = Some(value == "true"),
            "aria-expanded" => node.state.expanded = Some(value == "true"),
            "aria-selected" => node.state.selected = value == "true",
            "aria-required" => node.state.required = value == "true",
            "aria-live" => node.state.live = Some(value.clone()),
            "aria-level" => node.level = value.parse().ok(),
            _ => {}
        }
    }
}
