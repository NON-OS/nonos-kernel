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

mod async_handle;
mod async_submit;
mod async_wait;
mod sync;

pub use async_handle::AsyncIoHandle;
pub use async_submit::{submit_read_async, submit_write_async};
pub use async_wait::{wait_for_completion, wait_for_completion_interrupt};
pub use sync::{compare, flush, read_blocks, trim, write_blocks, write_zeroes};
