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

mod buffer;
mod reader;
mod writer;
mod syscall;
mod splice_support;

pub use buffer::{PipeBuffer, PIPE_BUF_SIZE};
pub use reader::{PipeReader, pipe_read};
pub use writer::{PipeWriter, pipe_write};
pub use syscall::{sys_pipe, sys_pipe2};
pub use splice_support::{pipe_splice_read, pipe_splice_write};
