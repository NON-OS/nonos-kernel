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

use super::types::Namespace;
use alloc::vec::Vec;

pub struct NamespaceManager {
    namespaces: Vec<Namespace>,
}

impl NamespaceManager {
    pub const fn new() -> Self {
        Self { namespaces: Vec::new() }
    }

    pub fn add(&mut self, ns: Namespace) {
        if self.get(ns.nsid).is_none() {
            self.namespaces.push(ns);
            self.namespaces.sort_by_key(|n| n.nsid);
        }
    }

    pub fn remove(&mut self, nsid: u32) -> Option<Namespace> {
        if let Some(pos) = self.namespaces.iter().position(|n| n.nsid == nsid) {
            Some(self.namespaces.remove(pos))
        } else {
            None
        }
    }

    pub fn get(&self, nsid: u32) -> Option<&Namespace> {
        self.namespaces.iter().find(|n| n.nsid == nsid)
    }
    pub fn get_mut(&mut self, nsid: u32) -> Option<&mut Namespace> {
        self.namespaces.iter_mut().find(|n| n.nsid == nsid)
    }
    pub fn first(&self) -> Option<&Namespace> {
        self.namespaces.first()
    }
    pub fn count(&self) -> usize {
        self.namespaces.len()
    }
    pub fn iter(&self) -> impl Iterator<Item = &Namespace> {
        self.namespaces.iter()
    }
    pub fn nsids(&self) -> Vec<u32> {
        self.namespaces.iter().map(|n| n.nsid).collect()
    }
    pub fn clear(&mut self) {
        self.namespaces.clear();
    }
    pub fn total_capacity_bytes(&self) -> u64 {
        self.namespaces.iter().map(|n| n.capacity_bytes()).sum()
    }
    pub fn total_size_bytes(&self) -> u64 {
        self.namespaces.iter().map(|n| n.size_bytes()).sum()
    }
}

impl Default for NamespaceManager {
    fn default() -> Self {
        Self::new()
    }
}
