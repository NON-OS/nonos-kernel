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

use super::tap::Tap;
use crate::nox::{NoxError, NoxResult};
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

pub struct TapRegistry {
    taps: BTreeMap<String, Tap>,
}

impl TapRegistry {
    pub fn new() -> Self {
        Self { taps: BTreeMap::new() }
    }

    pub fn add(&mut self, tap: Tap) -> NoxResult<()> {
        let name = tap.name();
        if self.taps.contains_key(&name) {
            return Err(NoxError::TapAlreadyExists(name));
        }
        self.taps.insert(name, tap);
        Ok(())
    }

    pub fn remove(&mut self, name: &str) -> NoxResult<Tap> {
        self.taps.remove(name).ok_or_else(|| NoxError::TapNotFound(String::from(name)))
    }

    pub fn get(&self, name: &str) -> Option<&Tap> {
        self.taps.get(name)
    }
    pub fn get_mut(&mut self, name: &str) -> Option<&mut Tap> {
        self.taps.get_mut(name)
    }
    pub fn contains(&self, name: &str) -> bool {
        self.taps.contains_key(name)
    }
    pub fn list(&self) -> Vec<&Tap> {
        self.taps.values().collect()
    }
    pub fn count(&self) -> usize {
        self.taps.len()
    }

    pub fn official(&self) -> Vec<&Tap> {
        self.taps.values().filter(|t| t.official).collect()
    }
}

impl Default for TapRegistry {
    fn default() -> Self {
        Self::new()
    }
}
