extern crate alloc;
use alloc::vec::Vec;
use super::node::NodeId;
use super::arena::DomArena;

pub fn ancestors(arena: &DomArena, node_id: NodeId) -> Vec<NodeId> {
    let mut result = Vec::new();
    let mut current = arena.get(node_id).and_then(|n| n.parent);
    while let Some(id) = current {
        result.push(id);
        current = arena.get(id).and_then(|n| n.parent);
    }
    result
}

pub fn descendants(arena: &DomArena, node_id: NodeId) -> Vec<NodeId> {
    let mut result = Vec::new();
    let mut stack = Vec::new();
    if let Some(node) = arena.get(node_id) {
        for child_id in node.children.iter().rev() {
            stack.push(*child_id);
        }
    }
    while let Some(id) = stack.pop() {
        result.push(id);
        if let Some(node) = arena.get(id) {
            for child_id in node.children.iter().rev() {
                stack.push(*child_id);
            }
        }
    }
    result
}

pub fn collect_text(arena: &DomArena, node_id: NodeId) -> alloc::string::String {
    let mut result = alloc::string::String::new();
    if let Some(node) = arena.get(node_id) {
        if let Some(ref text) = node.text_content {
            result.push_str(text);
        }
        for child_id in &node.children {
            result.push_str(&collect_text(arena, *child_id));
        }
    }
    result
}
