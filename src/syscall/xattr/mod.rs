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

mod fgetxattr;
mod flistxattr;
mod fremovexattr;
mod fsetxattr;
mod getxattr;
mod lgetxattr;
mod listxattr;
mod llistxattr;
mod lremovexattr;
mod lsetxattr;
mod removexattr;
mod setxattr;
mod storage;

pub use fgetxattr::handle_fgetxattr;
pub use flistxattr::handle_flistxattr;
pub use fremovexattr::handle_fremovexattr;
pub use fsetxattr::handle_fsetxattr;
pub use getxattr::handle_getxattr;
pub use lgetxattr::handle_lgetxattr;
pub use listxattr::handle_listxattr;
pub use llistxattr::handle_llistxattr;
pub use lremovexattr::handle_lremovexattr;
pub use lsetxattr::handle_lsetxattr;
pub use removexattr::handle_removexattr;
pub use setxattr::handle_setxattr;
pub use storage::*;
