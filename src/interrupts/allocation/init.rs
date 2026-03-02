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
use super::types::{KEYBOARD_VECTOR, RESERVED_VECTORS_END, SYSCALL_VECTOR, TIMER_VECTOR};

pub fn init() {
    let mut registry = REGISTRY.write();

    for i in 0..(RESERVED_VECTORS_END as usize) {
        registry.reserved[i] = true;
    }

    registry.reserved[TIMER_VECTOR as usize] = true;
    registry.reserved[KEYBOARD_VECTOR as usize] = true;
    registry.reserved[SYSCALL_VECTOR as usize] = true;
}
