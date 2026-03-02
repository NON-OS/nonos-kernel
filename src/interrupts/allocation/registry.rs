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

use spin::RwLock;

use super::types::{NoErrorHandler, VECTOR_COUNT};

pub struct Registry {
    pub reserved: [bool; VECTOR_COUNT],
    pub handlers: [Option<NoErrorHandler>; VECTOR_COUNT],
}

impl Registry {
    pub const fn new() -> Self {
        Self {
            reserved: [false; VECTOR_COUNT],
            handlers: [None; VECTOR_COUNT],
        }
    }
}

pub static REGISTRY: RwLock<Registry> = RwLock::new(Registry::new());
