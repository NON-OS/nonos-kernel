#[cfg(test)]
mod tests {
    use crate::apps::ecosystem::browser::engine::dom::*;
    use crate::apps::ecosystem::browser::engine::events::*;

    fn setup() -> (DomArena, NodeId, NodeId, NodeId) {
        let mut arena = DomArena::new();
        let root = arena.root_id();
        let parent = arena.create_element("div");
        let child = arena.create_element("span");
        append_child(&mut arena, root, parent);
        append_child(&mut arena, parent, child);
        (arena, root, parent, child)
    }

    #[test]
    fn test_dispatch_fires_listener() {
        let (arena, _, _, child) = setup();
        let mut store = EventListenerStore::new();
        store.add(
            child,
            "click",
            EventListener { callback_id: 1, capture: false, once: false, passive: false },
        );
        let mut event = DomEvent::new("click", child, true, true);
        let result = dispatch_event(&arena, &mut store, &mut event);
        assert!(result.callbacks_fired.contains(&1));
    }

    #[test]
    fn test_dispatch_bubbles_to_parent() {
        let (arena, _, parent, child) = setup();
        let mut store = EventListenerStore::new();
        store.add(
            parent,
            "click",
            EventListener { callback_id: 2, capture: false, once: false, passive: false },
        );
        let mut event = DomEvent::new("click", child, true, true);
        let result = dispatch_event(&arena, &mut store, &mut event);
        assert!(result.callbacks_fired.contains(&2));
    }

    #[test]
    fn test_stop_propagation_prevents_bubble() {
        let (arena, _, parent, child) = setup();
        let mut store = EventListenerStore::new();
        store.add(
            child,
            "click",
            EventListener { callback_id: 1, capture: false, once: false, passive: false },
        );
        store.add(
            parent,
            "click",
            EventListener { callback_id: 2, capture: false, once: false, passive: false },
        );
        let mut event = DomEvent::new("click", child, true, true);
        event.stop_propagation();
        let result = dispatch_event(&arena, &mut store, &mut event);
        assert!(!result.callbacks_fired.contains(&2));
    }

    #[test]
    fn test_capture_phase_fires_first() {
        let (arena, _, parent, child) = setup();
        let mut store = EventListenerStore::new();
        store.add(
            parent,
            "click",
            EventListener { callback_id: 10, capture: true, once: false, passive: false },
        );
        store.add(
            child,
            "click",
            EventListener { callback_id: 20, capture: false, once: false, passive: false },
        );
        let mut event = DomEvent::new("click", child, true, true);
        let result = dispatch_event(&arena, &mut store, &mut event);
        let pos_10 = result.callbacks_fired.iter().position(|&c| c == 10);
        let pos_20 = result.callbacks_fired.iter().position(|&c| c == 20);
        assert!(pos_10.is_some() && pos_20.is_some());
        assert!(pos_10.unwrap() < pos_20.unwrap());
    }

    #[test]
    fn test_prevent_default() {
        let (arena, _, _, child) = setup();
        let mut store = EventListenerStore::new();
        let mut event = DomEvent::new("click", child, true, true);
        event.prevent_default();
        let result = dispatch_event(&arena, &mut store, &mut event);
        assert!(result.default_prevented);
    }

    #[test]
    fn test_non_bubbling_event_stays_at_target() {
        let (arena, _, parent, child) = setup();
        let mut store = EventListenerStore::new();
        store.add(
            parent,
            "focus",
            EventListener { callback_id: 3, capture: false, once: false, passive: false },
        );
        let mut event = DomEvent::new("focus", child, false, false);
        let result = dispatch_event(&arena, &mut store, &mut event);
        assert!(!result.callbacks_fired.contains(&3));
    }

    #[test]
    fn test_once_listener_removed_after_dispatch() {
        let (arena, _, _, child) = setup();
        let mut store = EventListenerStore::new();
        store.add(
            child,
            "click",
            EventListener { callback_id: 5, capture: false, once: true, passive: false },
        );
        let mut event = DomEvent::new("click", child, true, true);
        dispatch_event(&arena, &mut store, &mut event);
        assert!(store.get(child, "click").is_empty());
    }
}
