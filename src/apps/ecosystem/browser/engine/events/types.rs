extern crate alloc;
use super::super::dom::NodeId;
use alloc::string::String;

#[derive(Debug, Clone)]
pub struct DomEvent {
    pub event_type: String,
    pub target: NodeId,
    pub current_target: NodeId,
    pub phase: EventPhase,
    pub bubbles: bool,
    pub cancelable: bool,
    pub default_prevented: bool,
    pub propagation_stopped: bool,
    pub immediate_propagation_stopped: bool,
    pub timestamp: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventPhase {
    None,
    Capturing,
    AtTarget,
    Bubbling,
}

impl DomEvent {
    pub fn new(event_type: &str, target: NodeId, bubbles: bool, cancelable: bool) -> Self {
        Self {
            event_type: String::from(event_type),
            target,
            current_target: target,
            phase: EventPhase::None,
            bubbles,
            cancelable,
            default_prevented: false,
            propagation_stopped: false,
            immediate_propagation_stopped: false,
            timestamp: 0,
        }
    }

    pub fn prevent_default(&mut self) {
        if self.cancelable {
            self.default_prevented = true;
        }
    }

    pub fn stop_propagation(&mut self) {
        self.propagation_stopped = true;
    }

    pub fn stop_immediate_propagation(&mut self) {
        self.immediate_propagation_stopped = true;
        self.propagation_stopped = true;
    }
}
