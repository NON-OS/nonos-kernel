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
use spin::Mutex;

use super::types::Node;

const NODE_CAP: usize = 128;
static STORE: Mutex<Vec<Node>> = Mutex::new(Vec::new());

pub fn replace(nodes: Vec<Node>) -> bool {
    if nodes.is_empty() || nodes.len() > NODE_CAP {
        return false;
    }
    *STORE.lock() = nodes;
    true
}

pub fn snapshot() -> Vec<Node> {
    STORE.lock().clone()
}

pub fn ready() -> bool {
    !STORE.lock().is_empty()
}
