extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

#[derive(Debug, Clone, PartialEq)]
pub enum Selector {
    Simple(SimpleSelector),
    Compound(Vec<SimpleSelector>),
    Descendant(Box<Selector>, Box<Selector>),
    Child(Box<Selector>, Box<Selector>),
    Adjacent(Box<Selector>, Box<Selector>),
    General(Box<Selector>, Box<Selector>),
    Universal,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SimpleSelector {
    pub tag: Option<String>,
    pub id: Option<String>,
    pub classes: Vec<String>,
    pub pseudo_classes: Vec<String>,
    pub attributes: Vec<AttributeSelector>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AttributeSelector {
    pub name: String,
    pub op: AttributeOp,
    pub value: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AttributeOp {
    Exists,
    Equals,
    Contains,
    StartsWith,
    EndsWith,
    DashMatch,
}

impl SimpleSelector {
    pub fn new() -> Self {
        Self {
            tag: None,
            id: None,
            classes: Vec::new(),
            pseudo_classes: Vec::new(),
            attributes: Vec::new(),
        }
    }

    pub fn with_tag(tag: String) -> Self {
        Self { tag: Some(tag), ..Self::new() }
    }

    pub fn with_id(id: String) -> Self {
        Self { id: Some(id), ..Self::new() }
    }

    pub fn with_class(class: String) -> Self {
        let mut s = Self::new();
        s.classes.push(class);
        s
    }
}
