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

pub mod error;
pub mod types;
pub mod open_file;
pub mod table;
pub mod fd_ops;
pub mod vfs_core;
pub mod vfs_dir;
pub mod vfs_file;
pub mod vfs_global;

#[cfg(test)]
mod fd_tests;

pub use error::{VfsError, VfsResult};
pub use types::*;
pub use open_file::OpenFile;
pub use fd_ops::*;
pub use vfs_core::VirtualFileSystem;
pub use vfs_global::*;
