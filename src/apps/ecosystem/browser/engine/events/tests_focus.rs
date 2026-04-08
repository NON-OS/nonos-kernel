#[cfg(test)]
mod tests {
    use crate::apps::ecosystem::browser::engine::events::focus::FocusManager;
    use crate::apps::ecosystem::browser::engine::dom::NodeId;

    #[test]
    fn test_focus_sets_active_element() {
        let mut fm = FocusManager::new();
        let node = NodeId(5);
        fm.focus(node);
        assert_eq!(fm.active_element, Some(node));
    }

    #[test]
    fn test_blur_clears_active_element() {
        let mut fm = FocusManager::new();
        fm.focus(NodeId(5));
        fm.blur();
        assert!(fm.active_element.is_none());
    }

    #[test]
    fn test_focus_returns_blurred_element() {
        let mut fm = FocusManager::new();
        let a = NodeId(1);
        let b = NodeId(2);
        fm.focus(a);
        let change = fm.focus(b);
        assert_eq!(change.blurred, Some(a));
        assert_eq!(change.focused, Some(b));
    }

    #[test]
    fn test_is_focused() {
        let mut fm = FocusManager::new();
        let node = NodeId(3);
        assert!(!fm.is_focused(node));
        fm.focus(node);
        assert!(fm.is_focused(node));
    }

    #[test]
    fn test_initial_state_no_focus() {
        let fm = FocusManager::new();
        assert!(fm.active_element.is_none());
    }
}
