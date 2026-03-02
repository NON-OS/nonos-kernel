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

use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NumaNode(pub u16);

#[derive(Debug, Clone)]
pub struct NumaTopology {
    pub(crate) node_count: u16,
    pub(crate) cpu_to_node: Vec<u16>,
}

impl NumaTopology {
    #[inline]
    pub fn new(node_count: u16, cpu_to_node: Vec<u16>) -> Result<Self, &'static str> {
        if node_count == 0 {
            return Err("EINVAL");
        }
        // Validate mapping entries are within node_count
        if !cpu_to_node.iter().all(|&n| (n as u16) < node_count) {
            return Err("EINVAL");
        }
        Ok(Self { node_count, cpu_to_node })
    }

    #[inline]
    pub fn node_count(&self) -> u16 {
        self.node_count
    }

    #[inline]
    pub fn cpu_to_node(&self, cpu_id: u32) -> u16 {
        let idx = cpu_id as usize;
        if idx < self.cpu_to_node.len() {
            self.cpu_to_node[idx]
        } else {
            0
        }
    }
}
