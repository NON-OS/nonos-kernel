extern crate alloc;
use super::super::types::{Node, NodeType};
use super::arena::DomArena;
use super::mutate::append_child;
use super::node::NodeId;

pub fn document_to_arena(root: &Node) -> DomArena {
    let mut arena = DomArena::new();
    let root_id = arena.root_id();
    convert_node(&mut arena, root, root_id);
    arena.needs_layout = false;
    arena
}

fn convert_node(arena: &mut DomArena, node: &Node, parent_id: NodeId) {
    let node_id = match &node.node_type {
        NodeType::Element(tag) => {
            let id = arena.create_element(tag);
            for (key, value) in &node.attributes {
                if let Some(n) = arena.get_mut(id) {
                    n.attributes.insert(key.clone(), value.clone());
                }
            }
            id
        }
        NodeType::Text(text) => {
            if text.trim().is_empty() {
                return;
            }
            arena.create_text_node(text)
        }
        NodeType::Comment(_) => return,
    };

    append_child(arena, parent_id, node_id);

    for child in &node.children {
        convert_node(arena, child, node_id);
    }
}
