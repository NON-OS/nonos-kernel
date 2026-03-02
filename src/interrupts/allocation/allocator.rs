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

use super::registry::REGISTRY;
use super::types::RESERVED_VECTORS_END;

pub fn allocate_vector() -> Option<u8> {
    let mut registry = REGISTRY.write();

    for vector in RESERVED_VECTORS_END..=255 {
        let idx = vector as usize;
        if !registry.reserved[idx] && registry.handlers[idx].is_none() {
            registry.reserved[idx] = true;
            return Some(vector);
        }
    }

    None
}

pub fn free_vector(vector: u8) -> Result<(), &'static str> {
    if vector < RESERVED_VECTORS_END {
        return Err("cannot free reserved vector");
    }

    let mut registry = REGISTRY.write();
    let idx = vector as usize;

    if !registry.reserved[idx] {
        return Err("vector not allocated");
    }

    registry.reserved[idx] = false;
    registry.handlers[idx] = None;

    Ok(())
}

pub fn is_vector_available(vector: u8) -> bool {
    if vector < RESERVED_VECTORS_END {
        return false;
    }

    let registry = REGISTRY.read();
    let idx = vector as usize;

    !registry.reserved[idx] && registry.handlers[idx].is_none()
}
