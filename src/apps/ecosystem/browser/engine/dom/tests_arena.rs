#[cfg(test)]
mod tests {
    use crate::apps::ecosystem::browser::engine::dom::*;

    #[test]
    fn test_create_element() {
        let mut arena = DomArena::new();
        let div = arena.create_element("div");
        assert_eq!(arena.get(div).unwrap().tag_name.as_deref(), Some("div"));
    }

    #[test]
    fn test_create_text_node() {
        let mut arena = DomArena::new();
        let text = arena.create_text_node("hello");
        assert_eq!(arena.get(text).unwrap().text_content.as_deref(), Some("hello"));
    }

    #[test]
    fn test_append_child_sets_parent() {
        let mut arena = DomArena::new();
        let parent = arena.create_element("div");
        let child = arena.create_element("span");
        append_child(&mut arena, parent, child);
        assert_eq!(arena.get(child).unwrap().parent, Some(parent));
        assert_eq!(arena.get(parent).unwrap().children.len(), 1);
    }

    #[test]
    fn test_append_child_sets_siblings() {
        let mut arena = DomArena::new();
        let parent = arena.create_element("div");
        let c1 = arena.create_element("a");
        let c2 = arena.create_element("b");
        append_child(&mut arena, parent, c1);
        append_child(&mut arena, parent, c2);
        assert_eq!(arena.get(c1).unwrap().next_sibling, Some(c2));
        assert_eq!(arena.get(c2).unwrap().prev_sibling, Some(c1));
    }

    #[test]
    fn test_remove_child() {
        let mut arena = DomArena::new();
        let parent = arena.create_element("div");
        let child = arena.create_element("span");
        append_child(&mut arena, parent, child);
        remove_child(&mut arena, parent, child);
        assert!(arena.get(parent).unwrap().children.is_empty());
        assert!(arena.get(child).unwrap().parent.is_none());
    }

    #[test]
    fn test_remove_middle_fixes_siblings() {
        let mut arena = DomArena::new();
        let p = arena.create_element("div");
        let (a, b, c) =
            (arena.create_element("a"), arena.create_element("b"), arena.create_element("c"));
        append_child(&mut arena, p, a);
        append_child(&mut arena, p, b);
        append_child(&mut arena, p, c);
        remove_child(&mut arena, p, b);
        assert_eq!(arena.get(a).unwrap().next_sibling, Some(c));
        assert_eq!(arena.get(c).unwrap().prev_sibling, Some(a));
    }

    #[test]
    fn test_insert_before() {
        let mut arena = DomArena::new();
        let p = arena.create_element("div");
        let (a, b) = (arena.create_element("a"), arena.create_element("b"));
        append_child(&mut arena, p, b);
        insert_before(&mut arena, p, a, b);
        let children = &arena.get(p).unwrap().children;
        assert_eq!(children[0], a);
        assert_eq!(children[1], b);
    }

    #[test]
    fn test_dirty_flag_on_mutation() {
        let mut arena = DomArena::new();
        arena.needs_layout = false;
        let _div = arena.create_element("div");
        assert!(arena.needs_layout);
    }

    #[test]
    fn test_node_count() {
        let mut arena = DomArena::new();
        arena.create_element("a");
        arena.create_element("b");
        assert_eq!(arena.node_count(), 3);
    }
}
