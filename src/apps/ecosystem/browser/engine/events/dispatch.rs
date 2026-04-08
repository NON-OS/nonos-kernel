extern crate alloc;
use alloc::vec::Vec;
use super::types::{DomEvent, EventPhase};
use super::listener::{EventListenerStore, EventCallback};
use super::super::dom::{DomArena, NodeId};
use super::super::dom::traverse::ancestors;

pub struct DispatchResult {
    pub default_prevented: bool,
    pub callbacks_fired: Vec<EventCallback>,
}

pub fn dispatch_event(
    arena: &DomArena,
    store: &mut EventListenerStore,
    event: &mut DomEvent,
) -> DispatchResult {
    let mut fired = Vec::new();
    let path = build_path(arena, event.target);

    event.phase = EventPhase::Capturing;
    for &node_id in path.iter().rev().skip(1) {
        event.current_target = node_id;
        fire_listeners(store, node_id, event, true, &mut fired);
        if event.propagation_stopped { return result(event, fired); }
    }

    event.phase = EventPhase::AtTarget;
    event.current_target = event.target;
    fire_listeners(store, event.target, event, true, &mut fired);
    if !event.propagation_stopped {
        fire_listeners(store, event.target, event, false, &mut fired);
    }
    if event.propagation_stopped { return result(event, fired); }

    if event.bubbles {
        event.phase = EventPhase::Bubbling;
        for &node_id in path.iter().rev().skip(1) {
            event.current_target = node_id;
            fire_listeners(store, node_id, event, false, &mut fired);
            if event.propagation_stopped { break; }
        }
    }

    cleanup_once(store, event, &path);
    result(event, fired)
}

fn build_path(arena: &DomArena, target: NodeId) -> Vec<NodeId> {
    let mut path = ancestors(arena, target);
    path.reverse();
    path.push(target);
    path
}

fn fire_listeners(
    store: &EventListenerStore,
    node: NodeId,
    event: &mut DomEvent,
    capture_phase: bool,
    fired: &mut Vec<EventCallback>,
) {
    let listeners = store.get(node, &event.event_type);
    for listener in listeners {
        if listener.capture != capture_phase { continue; }
        fired.push(listener.callback_id);
        if event.immediate_propagation_stopped { break; }
    }
}

fn cleanup_once(store: &mut EventListenerStore, event: &DomEvent, path: &[NodeId]) {
    for &node_id in path {
        store.remove_once_listeners(node_id, &event.event_type);
    }
}

fn result(event: &DomEvent, callbacks_fired: Vec<EventCallback>) -> DispatchResult {
    DispatchResult { default_prevented: event.default_prevented, callbacks_fired }
}
