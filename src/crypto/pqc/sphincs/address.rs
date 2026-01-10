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

pub const ADDR_TYPE_WOTS: u8 = 0;
pub const ADDR_TYPE_WOTS_PK: u8 = 1;
pub const ADDR_TYPE_TREE: u8 = 2;
pub const ADDR_TYPE_FORS_TREE: u8 = 3;
pub const ADDR_TYPE_FORS_ROOTS: u8 = 4;
pub const ADDR_TYPE_WOTS_PRF: u8 = 5;
pub const ADDR_TYPE_FORS_PRF: u8 = 6;

#[derive(Clone, Copy, Default)]
pub struct Address {
    pub layer: u32,
    pub tree: u64,
    pub addr_type: u8,
    pub keypair: u32,
    pub chain: u32,
    pub hash: u32,
    pub tree_height: u32,
    pub tree_index: u32,
}

impl Address {
    pub fn to_bytes(&self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[0..4].copy_from_slice(&self.layer.to_be_bytes());
        out[4..12].copy_from_slice(&self.tree.to_be_bytes());
        out[12] = self.addr_type;
        out[16..20].copy_from_slice(&self.keypair.to_be_bytes());
        out[20..24].copy_from_slice(&self.chain.to_be_bytes());
        out[24..28].copy_from_slice(&self.hash.to_be_bytes());
        out[28..32].copy_from_slice(&self.tree_index.to_be_bytes());
        out
    }

    pub fn set_layer(&mut self, layer: u32) { self.layer = layer; }
    pub fn set_tree(&mut self, tree: u64) { self.tree = tree; }
    pub fn set_type(&mut self, t: u8) { self.addr_type = t; }
    pub fn set_keypair(&mut self, kp: u32) { self.keypair = kp; }
    pub fn set_chain(&mut self, c: u32) { self.chain = c; }
    pub fn set_hash(&mut self, h: u32) { self.hash = h; }
    pub fn set_tree_height(&mut self, th: u32) { self.tree_height = th; }
    pub fn set_tree_index(&mut self, ti: u32) { self.tree_index = ti; }
}
