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

pub const MAX_LAYERS: usize = 32;

#[derive(Clone, Copy, Default)]
pub struct Layer {
    pub owner_pid: u32,
    pub surface_handle: u64,
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
    pub z: u32,
    pub in_use: bool,
}

pub struct SceneTable {
    entries: [Layer; MAX_LAYERS],
    count: usize,
}

impl SceneTable {
    pub const fn new() -> Self {
        Self { entries: [Layer { owner_pid: 0, surface_handle: 0, x: 0, y: 0, width: 0, height: 0, z: 0, in_use: false }; MAX_LAYERS], count: 0 }
    }

    pub fn submit(&mut self, layer: Layer) -> Result<(), ()> {
        for slot in self.entries.iter_mut() {
            if slot.in_use && slot.owner_pid == layer.owner_pid {
                *slot = layer;
                return Ok(());
            }
        }
        if self.count >= MAX_LAYERS {
            return Err(());
        }
        for slot in self.entries.iter_mut() {
            if !slot.in_use {
                *slot = layer;
                self.count += 1;
                return Ok(());
            }
        }
        Err(())
    }

    pub fn layers(&self) -> impl Iterator<Item = &Layer> {
        self.entries.iter().filter(|l| l.in_use)
    }

    pub fn z_sorted_snapshot(&self) -> ([Layer; MAX_LAYERS], usize) {
        let mut out = [Layer::default(); MAX_LAYERS];
        let mut n = 0;
        for layer in self.entries.iter().filter(|l| l.in_use) {
            out[n] = *layer;
            n += 1;
        }
        let mut i = 1;
        while i < n {
            let mut j = i;
            while j > 0 && out[j - 1].z > out[j].z {
                out.swap(j - 1, j);
                j -= 1;
            }
            i += 1;
        }
        (out, n)
    }

    pub fn drop_by_pid(&mut self, owner_pid: u32) -> u32 {
        let mut dropped = 0u32;
        for slot in self.entries.iter_mut() {
            if slot.in_use && slot.owner_pid == owner_pid {
                *slot = Layer::default();
                self.count = self.count.saturating_sub(1);
                dropped += 1;
            }
        }
        dropped
    }
}
