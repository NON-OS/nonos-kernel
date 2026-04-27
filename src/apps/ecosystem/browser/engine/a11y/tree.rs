extern crate alloc;
use super::roles;
use super::types::AccessibleNode;
use alloc::string::String;
use alloc::vec::Vec;

pub fn build_a11y_tree(
    tag: &str,
    attrs: &[(String, String)],
    text: &str,
    children: Vec<AccessibleNode>,
) -> AccessibleNode {
    let explicit_role = attrs.iter().find(|(k, _)| k == "role").map(|(_, v)| v.as_str());
    let role = if let Some(r) = explicit_role {
        roles::explicit::parse_role(r)
    } else {
        roles::implicit::implicit_role(tag)
    };
    let name = resolve_accessible_name(attrs, text);
    let mut node = AccessibleNode::new(role, &name);
    node.children = children;
    roles::aria_attrs::apply_aria_attrs(&mut node, attrs);
    if tag == "h1" || tag == "h2" || tag == "h3" || tag == "h4" || tag == "h5" || tag == "h6" {
        node.level = Some(tag.as_bytes()[1] as u32 - b'0' as u32);
    }
    node
}

fn resolve_accessible_name(attrs: &[(String, String)], text: &str) -> String {
    if let Some((_, v)) = attrs.iter().find(|(k, _)| k == "aria-label") {
        return v.clone();
    }
    if let Some((_, v)) = attrs.iter().find(|(k, _)| k == "alt") {
        return v.clone();
    }
    if let Some((_, v)) = attrs.iter().find(|(k, _)| k == "title") {
        return v.clone();
    }
    String::from(text)
}
