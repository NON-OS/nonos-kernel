extern crate alloc;
use alloc::string::String;
use super::types::{Selector, SimpleSelector};
use super::match_attr::matches_attribute;

pub struct NodeInfo<'a> {
    pub tag: &'a str,
    pub id: Option<&'a str>,
    pub classes: &'a [String],
    pub attributes: &'a [(String, String)],
    pub parent: Option<&'a NodeInfo<'a>>,
    pub prev_sibling_tag: Option<&'a str>,
}

pub fn matches_selector(node: &NodeInfo, selector: &Selector) -> bool {
    match selector {
        Selector::Universal => true,
        Selector::Simple(simple) => matches_simple(node, simple),
        Selector::Compound(parts) => parts.iter().all(|p| matches_simple(node, p)),
        Selector::Descendant(ancestor_sel, self_sel) => {
            matches_selector(node, self_sel) && has_matching_ancestor(node, ancestor_sel)
        }
        Selector::Child(parent_sel, self_sel) => {
            matches_selector(node, self_sel)
                && node.parent.map_or(false, |p| matches_selector(p, parent_sel))
        }
        Selector::Adjacent(prev_sel, self_sel) => {
            matches_selector(node, self_sel) && matches_adjacent(node, prev_sel)
        }
        Selector::General(_prev_sel, self_sel) => matches_selector(node, self_sel),
    }
}

fn has_matching_ancestor(node: &NodeInfo, selector: &Selector) -> bool {
    let mut current = node.parent;
    while let Some(ancestor) = current {
        if matches_selector(ancestor, selector) {
            return true;
        }
        current = ancestor.parent;
    }
    false
}

fn matches_adjacent(node: &NodeInfo, _prev_sel: &Selector) -> bool {
    node.prev_sibling_tag.is_some()
}

fn matches_simple(node: &NodeInfo, simple: &SimpleSelector) -> bool {
    if let Some(ref tag) = simple.tag {
        if !tag.eq_ignore_ascii_case(node.tag) {
            return false;
        }
    }
    if let Some(ref id) = simple.id {
        if node.id != Some(id.as_str()) {
            return false;
        }
    }
    for class in &simple.classes {
        if !node.classes.iter().any(|c| c == class) {
            return false;
        }
    }
    simple.attributes.iter().all(|attr_sel| matches_attribute(node, attr_sel))
}
