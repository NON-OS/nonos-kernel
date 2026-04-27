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

use super::numa::NumaDistances;
use super::table::Slit;

impl NumaDistances {
    pub fn nearest_neighbor(&self, node: usize) -> Option<usize> {
        if node >= self.node_count {
            return None;
        }
        let mut nearest = None;
        let mut min_distance = Slit::UNREACHABLE;
        for i in 0..self.node_count {
            if i == node {
                continue;
            }
            if let Some(d) = self.distance(i, node) {
                if d < min_distance && d != Slit::UNREACHABLE {
                    min_distance = d;
                    nearest = Some(i);
                }
            }
        }
        nearest
    }

    pub fn farthest_neighbor(&self, node: usize) -> Option<usize> {
        if node >= self.node_count {
            return None;
        }
        let mut farthest = None;
        let mut max_distance = 0u8;
        for i in 0..self.node_count {
            if i == node {
                continue;
            }
            if let Some(d) = self.distance(i, node) {
                if d > max_distance && d != Slit::UNREACHABLE {
                    max_distance = d;
                    farthest = Some(i);
                }
            }
        }
        farthest
    }

    pub fn is_reachable(&self, from: usize, to: usize) -> bool {
        self.distance(from, to).map(|d| d != Slit::UNREACHABLE).unwrap_or(false)
    }
}
