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

pub mod capsule_spawn;
mod context;
mod kernel_stack;
mod pending_stack_free;
mod user_stack;

pub(crate) use context::setup_initial_user_context;
pub(crate) use kernel_stack::allocate_kernel_stack;
pub(crate) use pending_stack_free::{
    defer_release as defer_kernel_stack_release, drain as drain_pending_kernel_stacks,
};
pub(crate) use user_stack::allocate_user_stack;
