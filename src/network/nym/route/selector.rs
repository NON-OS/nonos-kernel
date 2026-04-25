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

use crate::network::nym::directory::cache::get_directory_cache;
use crate::network::nym::error::NymError;
use crate::network::nym::types::{MixNode, NYM_MIX_LAYERS};
use alloc::vec::Vec;

pub struct PathSelector {
    excluded: Vec<[u8; 32]>,
}

pub fn select_path() -> Result<[MixNode; NYM_MIX_LAYERS], NymError> {
    PathSelector::new().select()
}

impl PathSelector {
    pub fn new() -> Self {
        Self { excluded: Vec::new() }
    }

    pub fn exclude(mut self, node_id: [u8; 32]) -> Self {
        self.excluded.push(node_id);
        self
    }

    pub fn select(&self) -> Result<[MixNode; NYM_MIX_LAYERS], NymError> {
        let cache = get_directory_cache().lock();
        let mut path: [Option<MixNode>; NYM_MIX_LAYERS] = [None, None, None, None, None];
        for layer in 1..=NYM_MIX_LAYERS as u8 {
            let candidates: Vec<_> = cache
                .mixnodes
                .iter()
                .filter(|n| n.layer == layer && n.is_healthy())
                .filter(|n| !self.excluded.contains(&n.id.0))
                .collect();
            if candidates.is_empty() {
                return Err(NymError::NoAvailableMixNodes);
            }
            let idx = crate::crypto::random_u32() as usize % candidates.len();
            path[(layer - 1) as usize] = Some(candidates[idx].clone());
        }
        Ok([
            path[0].clone().ok_or(NymError::NoAvailableMixNodes)?,
            path[1].clone().ok_or(NymError::NoAvailableMixNodes)?,
            path[2].clone().ok_or(NymError::NoAvailableMixNodes)?,
            path[3].clone().ok_or(NymError::NoAvailableMixNodes)?,
            path[4].clone().ok_or(NymError::NoAvailableMixNodes)?,
        ])
    }
}

impl Default for PathSelector {
    fn default() -> Self {
        Self::new()
    }
}
