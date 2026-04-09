extern crate alloc;
use alloc::string::String;
use super::types::DomEvent;
use super::super::dom::NodeId;

#[derive(Debug, Clone)]
pub struct KeyboardEvent {
    pub base: DomEvent,
    pub key: String,
    pub code: String,
    pub ctrl_key: bool,
    pub shift_key: bool,
    pub alt_key: bool,
    pub meta_key: bool,
}

impl KeyboardEvent {
    pub fn keydown(target: NodeId, key: &str, code: &str) -> Self {
        Self {
            base: DomEvent::new("keydown", target, true, true),
            key: String::from(key),
            code: String::from(code),
            ctrl_key: false,
            shift_key: false,
            alt_key: false,
            meta_key: false,
        }
    }

    pub fn keyup(target: NodeId, key: &str, code: &str) -> Self {
        Self {
            base: DomEvent::new("keyup", target, true, true),
            key: String::from(key),
            code: String::from(code),
            ctrl_key: false,
            shift_key: false,
            alt_key: false,
            meta_key: false,
        }
    }

    pub fn with_modifiers(mut self, ctrl: bool, shift: bool, alt: bool, meta: bool) -> Self {
        self.ctrl_key = ctrl;
        self.shift_key = shift;
        self.alt_key = alt;
        self.meta_key = meta;
        self
    }
}
