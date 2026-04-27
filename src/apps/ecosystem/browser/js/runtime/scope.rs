// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

extern crate alloc;
use super::value::JsValue;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

pub struct Scope {
    frames: Vec<BTreeMap<String, JsValue>>,
}

impl Scope {
    pub(super) fn new() -> Self {
        Self { frames: alloc::vec![BTreeMap::new()] }
    }
    pub(super) fn push(&mut self) {
        self.frames.push(BTreeMap::new());
    }
    pub(super) fn pop(&mut self) {
        if self.frames.len() > 1 {
            self.frames.pop();
        }
    }
    pub(super) fn declare(&mut self, name: String, val: JsValue) {
        if let Some(frame) = self.frames.last_mut() {
            frame.insert(name, val);
        }
    }
    pub(super) fn get(&self, name: &str) -> JsValue {
        for frame in self.frames.iter().rev() {
            if let Some(v) = frame.get(name) {
                return v.clone();
            }
        }
        JsValue::Undefined
    }
    pub(super) fn set(&mut self, name: &str, val: JsValue) -> bool {
        for frame in self.frames.iter_mut().rev() {
            if frame.contains_key(name) {
                frame.insert(String::from(name), val);
                return true;
            }
        }
        if let Some(frame) = self.frames.last_mut() {
            frame.insert(String::from(name), val);
        }
        true
    }
}
