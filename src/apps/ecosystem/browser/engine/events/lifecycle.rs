extern crate alloc;
use super::super::dom::NodeId;
use super::types::DomEvent;

pub fn dom_content_loaded(document_node: NodeId) -> DomEvent {
    DomEvent::new("DOMContentLoaded", document_node, true, false)
}

pub fn load_event(window_node: NodeId) -> DomEvent {
    DomEvent::new("load", window_node, false, false)
}

pub fn before_unload(window_node: NodeId) -> DomEvent {
    DomEvent::new("beforeunload", window_node, false, true)
}
