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

use super::table::Slit;
use alloc::vec::Vec;
use core::mem;

pub struct NumaDistances {
    pub node_count: usize,
    distances: Vec<u8>,
}

impl NumaDistances {
    pub fn from_slit(slit: &Slit) -> Self {
        let count = slit.locality_count as usize;
        let mut distances = Vec::with_capacity(count * count);
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
}
