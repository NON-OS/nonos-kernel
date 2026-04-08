#[cfg(test)]
mod tests {
    extern crate alloc;
    use alloc::string::String;
    use alloc::vec;
    use crate::apps::ecosystem::browser::engine::css::selector::types::*;
    use crate::apps::ecosystem::browser::engine::css::selector::specificity::Specificity;
    use crate::apps::ecosystem::browser::engine::css::selector::match_node::{matches_selector, NodeInfo};

    fn node_info<'a>(tag: &'a str, id: Option<&'a str>, classes: &'a [String], attrs: &'a [(String, String)]) -> NodeInfo<'a> {
        NodeInfo { tag, id, classes, attributes: attrs, parent: None, prev_sibling_tag: None }
    }

    #[test]
    fn test_specificity_ordering() {
        let type_sel = Specificity { inline: 0, ids: 0, classes: 0, types: 1 };
        let class_sel = Specificity { inline: 0, ids: 0, classes: 1, types: 0 };
        let id_sel = Specificity { inline: 0, ids: 1, classes: 0, types: 0 };
        let inline = Specificity::inline_style();
        assert!(type_sel < class_sel);
        assert!(class_sel < id_sel);
        assert!(id_sel < inline);
    }

    #[test]
    fn test_specificity_of_simple_tag() {
        let sel = Selector::Simple(SimpleSelector::with_tag(String::from("div")));
        let spec = Specificity::of(&sel);
        assert_eq!(spec.types, 1);
        assert_eq!(spec.classes, 0);
        assert_eq!(spec.ids, 0);
    }

    #[test]
    fn test_specificity_of_class() {
        let sel = Selector::Simple(SimpleSelector::with_class(String::from("foo")));
        let spec = Specificity::of(&sel);
        assert_eq!(spec.classes, 1);
    }

    #[test]
    fn test_specificity_of_id() {
        let sel = Selector::Simple(SimpleSelector::with_id(String::from("bar")));
        let spec = Specificity::of(&sel);
        assert_eq!(spec.ids, 1);
    }

    #[test]
    fn test_match_tag_selector() {
        let sel = Selector::Simple(SimpleSelector::with_tag(String::from("div")));
        let classes = vec![];
        let attrs = vec![];
        let node = node_info("div", None, &classes, &attrs);
        assert!(matches_selector(&node, &sel));
    }

    #[test]
    fn test_match_class_selector() {
        let sel = Selector::Simple(SimpleSelector::with_class(String::from("foo")));
        let classes = vec![String::from("foo"), String::from("bar")];
        let attrs = vec![];
        let node = node_info("div", None, &classes, &attrs);
        assert!(matches_selector(&node, &sel));
    }

    #[test]
    fn test_no_match_wrong_class() {
        let sel = Selector::Simple(SimpleSelector::with_class(String::from("baz")));
        let classes = vec![String::from("foo")];
        let attrs = vec![];
        let node = node_info("div", None, &classes, &attrs);
        assert!(!matches_selector(&node, &sel));
    }

    #[test]
    fn test_match_id_selector() {
        let sel = Selector::Simple(SimpleSelector::with_id(String::from("main")));
        let classes = vec![];
        let attrs = vec![];
        let node = node_info("div", Some("main"), &classes, &attrs);
        assert!(matches_selector(&node, &sel));
    }

    #[test]
    fn test_universal_matches_anything() {
        let classes = vec![];
        let attrs = vec![];
        let node = node_info("span", None, &classes, &attrs);
        assert!(matches_selector(&node, &Selector::Universal));
    }
}
