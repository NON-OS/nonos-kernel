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

use super::numa::NumaDistances;
use super::table::Slit;
use alloc::vec::Vec;

impl NumaDistances {
    pub fn nodes_within_distance(&self, node: usize, max_dist: u8) -> Vec<usize> {
        let mut result = Vec::new();
        if node >= self.node_count {
            return result;
        }
        for i in 0..self.node_count {
            if i == node {
                continue;
            }
            if let Some(d) = self.distance(i, node) {
                if d <= max_dist && d != Slit::UNREACHABLE {
                    result.push(i);
                }
            }
        }
        result
    }
}
