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
use super::types::{NoErrorHandler, RESERVED_VECTORS_END};

pub fn register_handler(vector: u8, handler: NoErrorHandler) -> Result<(), &'static str> {
    if vector < RESERVED_VECTORS_END {
        return Err("vector reserved for CPU exceptions");
    }

    let mut registry = REGISTRY.write();
    let idx = vector as usize;

    if registry.handlers[idx].is_some() {
        return Err("handler already registered");
    }

    registry.handlers[idx] = Some(handler);
    Ok(())
}

pub fn unregister_handler(vector: u8) -> Result<(), &'static str> {
    if vector < RESERVED_VECTORS_END {
        return Err("cannot unregister CPU exception handler");
    }

    let mut registry = REGISTRY.write();
    let idx = vector as usize;

    if registry.handlers[idx].is_none() {
        return Err("no handler registered");
    }

    registry.handlers[idx] = None;
    Ok(())
}

pub fn get_handler(vector: u8) -> Option<NoErrorHandler> {
    REGISTRY.read().handlers[vector as usize]
}
