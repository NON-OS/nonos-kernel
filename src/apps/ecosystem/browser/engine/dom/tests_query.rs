#[cfg(test)]
mod tests {
    extern crate alloc;
    use crate::apps::ecosystem::browser::engine::dom::*;
    use alloc::string::String;

    fn build_test_tree() -> DomArena {
        let mut arena = DomArena::new();
        let root = arena.root_id();
        let div = arena.create_element("div");
        if let Some(n) = arena.get_mut(div) {
            n.attributes.insert(String::from("id"), String::from("main"));
            n.attributes.insert(String::from("class"), String::from("container wide"));
        }
        append_child(&mut arena, root, div);

        let span = arena.create_element("span");
        if let Some(n) = arena.get_mut(span) {
            n.attributes.insert(String::from("class"), String::from("label"));
        }
        append_child(&mut arena, div, span);

        let p = arena.create_element("p");
        append_child(&mut arena, div, p);

        let text = arena.create_text_node("hello");
        append_child(&mut arena, p, text);

        arena
    }

    #[test]
    fn test_get_element_by_id() {
        let arena = build_test_tree();
        let found = get_element_by_id(&arena, "main");
        assert!(found.is_some());
        let node = arena.get(found.unwrap()).unwrap();
        assert_eq!(node.tag_name.as_deref(), Some("div"));
    }

    #[test]
    fn test_get_element_by_id_not_found() {
        let arena = build_test_tree();
        assert!(get_element_by_id(&arena, "nonexistent").is_none());
    }

    #[test]
    fn test_get_elements_by_class_name() {
        let arena = build_test_tree();
        let found = get_elements_by_class_name(&arena, "container");
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn test_get_elements_by_class_name_multi() {
        let arena = build_test_tree();
        let found = get_elements_by_class_name(&arena, "wide");
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn test_get_elements_by_tag_name() {
        let arena = build_test_tree();
        let found = get_elements_by_tag_name(&arena, "span");
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn test_collect_text() {
        let arena = build_test_tree();
        let p_nodes = get_elements_by_tag_name(&arena, "p");
        let text = super::super::traverse::collect_text(&arena, p_nodes[0]);
        assert_eq!(text, "hello");
    }

    #[test]
    fn test_descendants_count() {
        let arena = build_test_tree();
        let all = super::super::traverse::descendants(&arena, arena.root_id());
        assert_eq!(all.len(), 4);
    }

    #[test]
    fn test_ancestors() {
        let arena = build_test_tree();
        let spans = get_elements_by_tag_name(&arena, "span");
        let ancestors = super::super::traverse::ancestors(&arena, spans[0]);
        assert!(ancestors.len() >= 2);
    }
}
