extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DomNodeType {
    Document,
    Element,
    Text,
    Comment,
}

#[derive(Debug, Clone)]
pub struct DomNode {
    pub id: NodeId,
    pub node_type: DomNodeType,
    pub tag_name: Option<String>,
    pub attributes: BTreeMap<String, String>,
    pub parent: Option<NodeId>,
    pub children: Vec<NodeId>,
    pub next_sibling: Option<NodeId>,
    pub prev_sibling: Option<NodeId>,
    pub text_content: Option<String>,
}

impl DomNode {
    pub fn element(id: NodeId, tag: String) -> Self {
        Self {
            id, node_type: DomNodeType::Element, tag_name: Some(tag),
            attributes: BTreeMap::new(), parent: None, children: Vec::new(),
            next_sibling: None, prev_sibling: None, text_content: None,
        }
    }

    pub fn text(id: NodeId, content: String) -> Self {
        Self {
            id, node_type: DomNodeType::Text, tag_name: None,
            attributes: BTreeMap::new(), parent: None, children: Vec::new(),
            next_sibling: None, prev_sibling: None, text_content: Some(content),
        }
    }

    pub fn document(id: NodeId) -> Self {
        Self {
            id, node_type: DomNodeType::Document, tag_name: None,
            attributes: BTreeMap::new(), parent: None, children: Vec::new(),
            next_sibling: None, prev_sibling: None, text_content: None,
        }
    }

    pub fn get_id_attr(&self) -> Option<&str> {
        self.attributes.get("id").map(|s| s.as_str())
    }

    pub fn get_class_list(&self) -> Vec<&str> {
        self.attributes.get("class")
            .map(|c| c.split_whitespace().collect())
            .unwrap_or_default()
    }
}
