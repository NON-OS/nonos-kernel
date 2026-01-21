// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use super::sdt::SdtHeader;
use alloc::vec::Vec;
use core::mem;

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct Slit {
    pub header: SdtHeader,
    pub locality_count: u64,
}

impl Slit {
    pub const LOCAL_DISTANCE: u8 = 10;
    pub const UNREACHABLE: u8 = 255;

    pub fn matrix_offset(&self) -> usize {
        mem::size_of::<Self>()
    }

    pub fn matrix_size(&self) -> usize {
        let count = self.locality_count as usize;
        count * count
    }

    pub fn distance(&self, from: usize, to: usize) -> Option<u8> {
        let count = self.locality_count as usize;
        if from >= count || to >= count {
            return None;
        }
        // SAFETY: Caller ensures SLIT table memory is valid
        unsafe {
            let matrix = (self as *const Self as *const u8).add(mem::size_of::<Self>());
            Some(*matrix.add(from * count + to))
        }
    }

    pub fn is_valid(&self) -> bool {
        let count = self.locality_count as usize;
        if count == 0 {
            return false;
        }
        for i in 0..count {
            if self.distance(i, i) != Some(Self::LOCAL_DISTANCE) {
                return false;
            }
        }
        true
    }

    pub fn is_symmetric(&self) -> bool {
        let count = self.locality_count as usize;
        for i in 0..count {
            for j in (i + 1)..count {
                if self.distance(i, j) != self.distance(j, i) {
                    return false;
                }
            }
        }
        true
    }
}

pub struct NumaDistances {
    pub node_count: usize,
    distances: Vec<u8>,
}

impl NumaDistances {
    pub fn from_slit(slit: &Slit) -> Self {
        let count = slit.locality_count as usize;
        let mut distances = Vec::with_capacity(count * count);
        // SAFETY: SLIT table memory is valid during parsing
        unsafe {
            let matrix = (slit as *const Slit as *const u8).add(mem::size_of::<Slit>());
            for i in 0..(count * count) {
                distances.push(*matrix.add(i));
            }
        }
        Self { node_count: count, distances }
    }

    pub fn new_simple(node_count: usize, remote_distance: u8) -> Self {
        let mut distances = Vec::with_capacity(node_count * node_count);
        for i in 0..node_count {
            for j in 0..node_count {
                if i == j {
                    distances.push(Slit::LOCAL_DISTANCE);
                } else {
                    distances.push(remote_distance);
                }
            }
        }
        Self { node_count, distances }
    }

    pub fn new_uniform(node_count: usize) -> Self {
        Self::new_simple(node_count, 20)
    }

    pub fn distance(&self, from: usize, to: usize) -> Option<u8> {
        if from >= self.node_count || to >= self.node_count {
            return None;
        }
        Some(self.distances[from * self.node_count + to])
    }

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
            let d = self.distances[node * self.node_count + i];
            if d < min_distance && d != Slit::UNREACHABLE {
                min_distance = d;
                nearest = Some(i);
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
            let d = self.distances[node * self.node_count + i];
            if d > max_distance && d != Slit::UNREACHABLE {
                max_distance = d;
                farthest = Some(i);
            }
        }
        farthest
    }

    pub fn nodes_within_distance(&self, node: usize, max_dist: u8) -> Vec<usize> {
        let mut result = Vec::new();
        if node >= self.node_count {
            return result;
        }
        for i in 0..self.node_count {
            if i == node {
                continue;
            }
            let d = self.distances[node * self.node_count + i];
            if d <= max_dist && d != Slit::UNREACHABLE {
                result.push(i);
            }
        }
        result
    }

    pub fn is_reachable(&self, from: usize, to: usize) -> bool {
        self.distance(from, to).map(|d| d != Slit::UNREACHABLE).unwrap_or(false)
    }
}
