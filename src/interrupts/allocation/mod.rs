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

mod allocator;
mod handlers;
mod init;
mod registry;
mod types;

pub use allocator::{allocate_vector, free_vector, is_vector_available};
pub use handlers::{get_handler, register_handler, unregister_handler};
pub use init::init;
pub use registry::REGISTRY;
pub use types::{
    ErrorCodeHandler, NoErrorHandler, KEYBOARD_VECTOR, RESERVED_VECTORS_END, SYSCALL_VECTOR,
    TIMER_VECTOR, VECTOR_COUNT,
};
