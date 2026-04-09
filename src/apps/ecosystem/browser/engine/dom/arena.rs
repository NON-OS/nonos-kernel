extern crate alloc;
use alloc::vec::Vec;
use alloc::string::String;
use super::node::{NodeId, DomNode};

pub struct DomArena {
    pub nodes: Vec<DomNode>,
    pub needs_layout: bool,
    next_id: u32,
}

impl DomArena {
    pub fn new() -> Self {
        let root = DomNode::document(NodeId(0));
        Self { nodes: alloc::vec![root], needs_layout: false, next_id: 1 }
    }

    pub fn get(&self, id: NodeId) -> Option<&DomNode> {
        self.nodes.get(id.0 as usize)
    }

    pub fn get_mut(&mut self, id: NodeId) -> Option<&mut DomNode> {
        self.nodes.get_mut(id.0 as usize)
    }

    pub fn root_id(&self) -> NodeId {
        NodeId(0)
    }

    pub fn create_element(&mut self, tag: &str) -> NodeId {
        let id = NodeId(self.next_id);
        self.next_id += 1;
        self.nodes.push(DomNode::element(id, String::from(tag)));
        self.needs_layout = true;
        id
    }

    pub fn create_text_node(&mut self, text: &str) -> NodeId {
        let id = NodeId(self.next_id);
        self.next_id += 1;
        self.nodes.push(DomNode::text(id, String::from(text)));
        self.needs_layout = true;
        id
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }
}
