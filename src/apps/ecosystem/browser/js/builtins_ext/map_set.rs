extern crate alloc;
use super::super::runtime::JsValue;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

pub struct JsMap {
    entries: BTreeMap<String, JsValue>,
}

pub struct JsSet {
    values: Vec<String>,
}

impl JsMap {
    pub fn new() -> Self {
        Self { entries: BTreeMap::new() }
    }

    pub fn set(&mut self, key: &str, value: JsValue) {
        self.entries.insert(String::from(key), value);
    }

    pub fn get(&self, key: &str) -> JsValue {
        self.entries.get(key).cloned().unwrap_or(JsValue::Undefined)
    }

    pub fn has(&self, key: &str) -> bool {
        self.entries.contains_key(key)
    }

    pub fn delete(&mut self, key: &str) -> bool {
        self.entries.remove(key).is_some()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn size(&self) -> usize {
        self.entries.len()
    }
}

impl JsSet {
    pub fn new() -> Self {
        Self { values: Vec::new() }
    }

    pub fn add(&mut self, value: &str) {
        if !self.has(value) {
            self.values.push(String::from(value));
        }
    }

    pub fn has(&self, value: &str) -> bool {
        self.values.iter().any(|v| v == value)
    }

    pub fn delete(&mut self, value: &str) -> bool {
        let before = self.values.len();
        self.values.retain(|v| v != value);
        self.values.len() < before
    }

    pub fn clear(&mut self) {
        self.values.clear();
    }

    pub fn size(&self) -> usize {
        self.values.len()
    }
}
