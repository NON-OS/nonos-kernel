// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

extern crate alloc;

use crate::apps::ecosystem::browser::engine::types::document::{Document, Node, NodeType};
use crate::test::framework::TestResult;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

pub(crate) fn test_node_type_element() -> TestResult {
    let node_type = NodeType::Element(String::from("div"));
    match node_type {
        NodeType::Element(name) => {
            if name != "div" {
                return TestResult::Fail;
            }
        }
        _ => return TestResult::Fail,
    }
    TestResult::Pass
}

pub(crate) fn test_node_type_text() -> TestResult {
    let node_type = NodeType::Text(String::from("Hello World"));
    match node_type {
        NodeType::Text(content) => {
            if content != "Hello World" {
                return TestResult::Fail;
            }
        }
        _ => return TestResult::Fail,
    }
    TestResult::Pass
}

pub(crate) fn test_node_type_comment() -> TestResult {
    let node_type = NodeType::Comment(String::from("This is a comment"));
    match node_type {
        NodeType::Comment(content) => {
            if content != "This is a comment" {
                return TestResult::Fail;
            }
        }
        _ => return TestResult::Fail,
    }
    TestResult::Pass
}

pub(crate) fn test_node_new_element() -> TestResult {
    let node = Node {
        node_type: NodeType::Element(String::from("p")),
        children: Vec::new(),
        attributes: Vec::new(),
    };
    if node.children.len() != 0 {
        return TestResult::Fail;
    }
    if node.attributes.len() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_with_children() -> TestResult {
    let child = Node {
        node_type: NodeType::Text(String::from("text")),
        children: Vec::new(),
        attributes: Vec::new(),
    };
    let parent = Node {
        node_type: NodeType::Element(String::from("div")),
        children: vec![child],
        attributes: Vec::new(),
    };
    if parent.children.len() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_with_attributes() -> TestResult {
    let node = Node {
        node_type: NodeType::Element(String::from("a")),
        children: Vec::new(),
        attributes: vec![
            (String::from("href"), String::from("https://example.com")),
            (String::from("target"), String::from("_blank")),
        ],
    };
    if node.attributes.len() != 2 {
        return TestResult::Fail;
    }
    if node.attributes[0].0 != "href" {
        return TestResult::Fail;
    }
    if node.attributes[0].1 != "https://example.com" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_document_new() -> TestResult {
    let root = Node {
        node_type: NodeType::Element(String::from("html")),
        children: Vec::new(),
        attributes: Vec::new(),
    };
    let doc = Document {
        title: String::from("Test Page"),
        root,
        links: Vec::new(),
        forms: Vec::new(),
        images: Vec::new(),
        hidden_classes: Vec::new(),
        noscript_redirect: None,
    };
    if doc.title != "Test Page" {
        return TestResult::Fail;
    }
    if doc.links.len() != 0 {
        return TestResult::Fail;
    }
    if doc.forms.len() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_document_with_title() -> TestResult {
    let root = Node {
        node_type: NodeType::Element(String::from("html")),
        children: Vec::new(),
        attributes: Vec::new(),
    };
    let doc = Document {
        title: String::from("My Website - Home"),
        root,
        links: Vec::new(),
        forms: Vec::new(),
        images: Vec::new(),
        hidden_classes: Vec::new(),
        noscript_redirect: None,
    };
    if doc.title != "My Website - Home" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_document_noscript_redirect() -> TestResult {
    let root = Node {
        node_type: NodeType::Element(String::from("html")),
        children: Vec::new(),
        attributes: Vec::new(),
    };
    let doc = Document {
        title: String::from(""),
        root,
        links: Vec::new(),
        forms: Vec::new(),
        images: Vec::new(),
        hidden_classes: Vec::new(),
        noscript_redirect: Some(String::from("https://example.com/fallback")),
    };
    if doc.noscript_redirect.is_none() {
        return TestResult::Fail;
    }
    if doc.noscript_redirect.unwrap() != "https://example.com/fallback" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_document_hidden_classes() -> TestResult {
    let root = Node {
        node_type: NodeType::Element(String::from("html")),
        children: Vec::new(),
        attributes: Vec::new(),
    };
    let doc = Document {
        title: String::from(""),
        root,
        links: Vec::new(),
        forms: Vec::new(),
        images: Vec::new(),
        hidden_classes: vec![String::from("hidden"), String::from("invisible")],
        noscript_redirect: None,
    };
    if doc.hidden_classes.len() != 2 {
        return TestResult::Fail;
    }
    if doc.hidden_classes[0] != "hidden" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_type_clone() -> TestResult {
    let original = NodeType::Element(String::from("div"));
    let cloned = original.clone();
    match cloned {
        NodeType::Element(name) => {
            if name != "div" {
                return TestResult::Fail;
            }
        }
        _ => return TestResult::Fail,
    }
    TestResult::Pass
}

pub(crate) fn test_node_clone() -> TestResult {
    let node = Node {
        node_type: NodeType::Element(String::from("span")),
        children: Vec::new(),
        attributes: vec![(String::from("class"), String::from("test"))],
    };
    let cloned = node.clone();
    if cloned.attributes.len() != 1 {
        return TestResult::Fail;
    }
    if cloned.attributes[0].1 != "test" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_document_clone() -> TestResult {
    let root = Node {
        node_type: NodeType::Element(String::from("html")),
        children: Vec::new(),
        attributes: Vec::new(),
    };
    let doc = Document {
        title: String::from("Clone Test"),
        root,
        links: Vec::new(),
        forms: Vec::new(),
        images: Vec::new(),
        hidden_classes: Vec::new(),
        noscript_redirect: None,
    };
    let cloned = doc.clone();
    if cloned.title != "Clone Test" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_nested_nodes() -> TestResult {
    let text = Node {
        node_type: NodeType::Text(String::from("Hello")),
        children: Vec::new(),
        attributes: Vec::new(),
    };
    let span = Node {
        node_type: NodeType::Element(String::from("span")),
        children: vec![text],
        attributes: Vec::new(),
    };
    let div = Node {
        node_type: NodeType::Element(String::from("div")),
        children: vec![span],
        attributes: Vec::new(),
    };
    if div.children.len() != 1 {
        return TestResult::Fail;
    }
    if div.children[0].children.len() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
