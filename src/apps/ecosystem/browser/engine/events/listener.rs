extern crate alloc;
use super::super::dom::NodeId;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

pub type EventCallback = u32;

#[derive(Debug, Clone)]
pub struct EventListener {
    pub callback_id: EventCallback,
    pub capture: bool,
    pub once: bool,
    pub passive: bool,
}

pub struct EventListenerStore {
    listeners: BTreeMap<(NodeId, String), Vec<EventListener>>,
}

impl EventListenerStore {
    pub fn new() -> Self {
        Self { listeners: BTreeMap::new() }
    }

    pub fn add(&mut self, node: NodeId, event_type: &str, listener: EventListener) {
        let key = (node, String::from(event_type));
        self.listeners.entry(key).or_insert_with(Vec::new).push(listener);
    }

    pub fn remove(&mut self, node: NodeId, event_type: &str, callback_id: EventCallback) {
        let key = (node, String::from(event_type));
        if let Some(list) = self.listeners.get_mut(&key) {
            list.retain(|l| l.callback_id != callback_id);
        }
    }

    pub fn get(&self, node: NodeId, event_type: &str) -> &[EventListener] {
        let key = (node, String::from(event_type));
        self.listeners.get(&key).map(|v| v.as_slice()).unwrap_or(&[])
    }

    pub fn remove_once_listeners(&mut self, node: NodeId, event_type: &str) {
        let key = (node, String::from(event_type));
        if let Some(list) = self.listeners.get_mut(&key) {
            list.retain(|l| !l.once);
        }
    }
}
