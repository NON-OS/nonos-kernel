// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

extern crate alloc;

use crate::apps::ecosystem::browser::engine::types::document::{Node, NodeType};
use crate::test::framework::TestResult;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

pub(crate) fn test_node_type_element_creation() -> TestResult {
    let node_type = NodeType::Element(String::from("div"));
    match &node_type {
        NodeType::Element(name) => {
            if name != "div" {
                return TestResult::Fail;
            }
        }
        _ => return TestResult::Fail,
    }
    TestResult::Pass
}

pub(crate) fn test_node_type_text_creation() -> TestResult {
    let node_type = NodeType::Text(String::from("Sample text content"));
    match &node_type {
        NodeType::Text(content) => {
            if content != "Sample text content" {
                return TestResult::Fail;
            }
        }
        _ => return TestResult::Fail,
    }
    TestResult::Pass
}

pub(crate) fn test_node_type_comment_creation() -> TestResult {
    let node_type = NodeType::Comment(String::from("HTML comment"));
    match &node_type {
        NodeType::Comment(content) => {
            if content != "HTML comment" {
                return TestResult::Fail;
            }
        }
        _ => return TestResult::Fail,
    }
    TestResult::Pass
}

pub(crate) fn test_node_empty_children() -> TestResult {
    let node = Node {
        node_type: NodeType::Element(String::from("br")),
        children: Vec::new(),
        attributes: Vec::new(),
    };
    if !node.children.is_empty() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_with_single_child() -> TestResult {
    let child = Node {
        node_type: NodeType::Text(String::from("child text")),
        children: Vec::new(),
        attributes: Vec::new(),
    };
    let parent = Node {
        node_type: NodeType::Element(String::from("p")),
        children: vec![child],
        attributes: Vec::new(),
    };
    if parent.children.len() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_with_multiple_children() -> TestResult {
    let child1 = Node {
        node_type: NodeType::Text(String::from("first")),
        children: Vec::new(),
        attributes: Vec::new(),
    };
    let child2 = Node {
        node_type: NodeType::Text(String::from("second")),
        children: Vec::new(),
        attributes: Vec::new(),
    };
    let child3 = Node {
        node_type: NodeType::Text(String::from("third")),
        children: Vec::new(),
        attributes: Vec::new(),
    };
    let parent = Node {
        node_type: NodeType::Element(String::from("div")),
        children: vec![child1, child2, child3],
        attributes: Vec::new(),
    };
    if parent.children.len() != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_single_attribute() -> TestResult {
    let node = Node {
        node_type: NodeType::Element(String::from("a")),
        children: Vec::new(),
        attributes: vec![(String::from("href"), String::from("https://example.com"))],
    };
    if node.attributes.len() != 1 {
        return TestResult::Fail;
    }
    if node.attributes[0].0 != "href" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_multiple_attributes() -> TestResult {
    let node = Node {
        node_type: NodeType::Element(String::from("input")),
        children: Vec::new(),
        attributes: vec![
            (String::from("type"), String::from("text")),
            (String::from("name"), String::from("username")),
            (String::from("placeholder"), String::from("Enter username")),
        ],
    };
    if node.attributes.len() != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_class_attribute() -> TestResult {
    let node = Node {
        node_type: NodeType::Element(String::from("div")),
        children: Vec::new(),
        attributes: vec![(String::from("class"), String::from("container main-content"))],
    };
    if node.attributes[0].1 != "container main-content" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_id_attribute() -> TestResult {
    let node = Node {
        node_type: NodeType::Element(String::from("section")),
        children: Vec::new(),
        attributes: vec![(String::from("id"), String::from("main-section"))],
    };
    if node.attributes[0].0 != "id" {
        return TestResult::Fail;
    }
    if node.attributes[0].1 != "main-section" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_deeply_nested() -> TestResult {
    let text = Node {
        node_type: NodeType::Text(String::from("deep")),
        children: Vec::new(),
        attributes: Vec::new(),
    };
    let level3 = Node {
        node_type: NodeType::Element(String::from("span")),
        children: vec![text],
        attributes: Vec::new(),
    };
    let level2 = Node {
        node_type: NodeType::Element(String::from("p")),
        children: vec![level3],
        attributes: Vec::new(),
    };
    let level1 = Node {
        node_type: NodeType::Element(String::from("div")),
        children: vec![level2],
        attributes: Vec::new(),
    };
    if level1.children.len() != 1 {
        return TestResult::Fail;
    }
    if level1.children[0].children.len() != 1 {
        return TestResult::Fail;
    }
    if level1.children[0].children[0].children.len() != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_clone() -> TestResult {
    let node = Node {
        node_type: NodeType::Element(String::from("article")),
        children: Vec::new(),
        attributes: vec![(String::from("data-id"), String::from("123"))],
    };
    let cloned = node.clone();
    if cloned.attributes.len() != 1 {
        return TestResult::Fail;
    }
    if cloned.attributes[0].1 != "123" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_type_clone() -> TestResult {
    let original = NodeType::Element(String::from("header"));
    let cloned = original.clone();
    match cloned {
        NodeType::Element(name) => {
            if name != "header" {
                return TestResult::Fail;
            }
        }
        _ => return TestResult::Fail,
    }
    TestResult::Pass
}

pub(crate) fn test_node_mixed_children() -> TestResult {
    let text = Node {
        node_type: NodeType::Text(String::from("Hello ")),
        children: Vec::new(),
        attributes: Vec::new(),
    };
    let bold = Node {
        node_type: NodeType::Element(String::from("b")),
        children: vec![Node {
            node_type: NodeType::Text(String::from("World")),
            children: Vec::new(),
            attributes: Vec::new(),
        }],
        attributes: Vec::new(),
    };
    let paragraph = Node {
        node_type: NodeType::Element(String::from("p")),
        children: vec![text, bold],
        attributes: Vec::new(),
    };
    if paragraph.children.len() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_node_data_attributes() -> TestResult {
    let node = Node {
        node_type: NodeType::Element(String::from("div")),
        children: Vec::new(),
        attributes: vec![
            (String::from("data-value"), String::from("42")),
            (String::from("data-enabled"), String::from("true")),
        ],
    };
    if node.attributes.len() != 2 {
        return TestResult::Fail;
    }
    if node.attributes[0].0 != "data-value" {
        return TestResult::Fail;
    }
    TestResult::Pass
}
