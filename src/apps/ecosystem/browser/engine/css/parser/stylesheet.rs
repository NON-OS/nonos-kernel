extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use super::super::selector::Selector;
use super::super::types::CssValue;

#[derive(Debug, Clone)]
pub struct Stylesheet {
    pub rules: Vec<Rule>,
}

#[derive(Debug, Clone)]
pub struct Rule {
    pub selectors: Vec<Selector>,
    pub declarations: Vec<Declaration>,
    pub media_query: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Declaration {
    pub property: String,
    pub value: CssValue,
    pub important: bool,
}

impl Stylesheet {
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    pub fn merge(&mut self, other: Stylesheet) {
        self.rules.extend(other.rules);
    }
}

impl Rule {
    pub fn new(selectors: Vec<Selector>, declarations: Vec<Declaration>) -> Self {
        Self { selectors, declarations, media_query: None }
    }
}

impl Declaration {
    pub fn new(property: String, value: CssValue) -> Self {
        Self { property, value, important: false }
    }

    pub fn important(mut self) -> Self {
        self.important = true;
        self
    }
}
