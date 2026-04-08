extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use super::node::{NodeId, DomNodeType};
use super::arena::DomArena;
use super::traverse::descendants;

pub fn get_element_by_id(arena: &DomArena, id_value: &str) -> Option<NodeId> {
    for node_id in descendants(arena, arena.root_id()) {
        if let Some(node) = arena.get(node_id) {
            if node.get_id_attr() == Some(id_value) {
                return Some(node_id);
            }
        }
    }
    None
}

pub fn get_elements_by_class_name(arena: &DomArena, class: &str) -> Vec<NodeId> {
    let mut result = Vec::new();
    for node_id in descendants(arena, arena.root_id()) {
        if let Some(node) = arena.get(node_id) {
            if node.get_class_list().iter().any(|c| *c == class) {
                result.push(node_id);
            }
        }
    }
    result
}

pub fn get_elements_by_tag_name(arena: &DomArena, tag: &str) -> Vec<NodeId> {
    let mut result = Vec::new();
    let lower = tag.to_ascii_lowercase();
    for node_id in descendants(arena, arena.root_id()) {
        if let Some(node) = arena.get(node_id) {
            if node.node_type == DomNodeType::Element {
                if let Some(ref t) = node.tag_name {
                    if t.eq_ignore_ascii_case(&lower) {
                        result.push(node_id);
                    }
                }
            }
        }
    }
    result
}

pub fn query_selector(arena: &DomArena, selector_str: &str) -> Option<NodeId> {
    let results = query_selector_all(arena, selector_str);
    results.into_iter().next()
}

pub fn query_selector_all(arena: &DomArena, selector_str: &str) -> Vec<NodeId> {
    let selectors = super::super::css::parser::parse_selector_string(selector_str);
    let mut result = Vec::new();
    for node_id in descendants(arena, arena.root_id()) {
        if node_matches_any(arena, node_id, &selectors) {
            result.push(node_id);
        }
    }
    result
}

fn node_matches_any(arena: &DomArena, node_id: NodeId, selectors: &[super::super::css::Selector]) -> bool {
    let node = match arena.get(node_id) {
        Some(n) => n,
        None => return false,
    };
    let tag = node.tag_name.as_deref().unwrap_or("");
    let id_attr = node.get_id_attr();
    let classes: Vec<String> = node.get_class_list().iter().map(|s| String::from(*s)).collect();
    let attrs: Vec<(String, String)> = node.attributes.iter().map(|(k, v)| (k.clone(), v.clone())).collect();

    let info = super::super::css::selector::match_node::NodeInfo {
        tag, id: id_attr, classes: &classes, attributes: &attrs, parent: None, prev_sibling_tag: None,
    };

    selectors.iter().any(|sel| super::super::css::selector::matches_selector(&info, sel))
}
