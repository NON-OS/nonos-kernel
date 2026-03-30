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

mod compile;
mod dispatcher;
mod prove;
mod stats;
mod verify;

pub use compile::sys_zk_compile_circuit;
pub use dispatcher::handle_zk_syscall;
pub use prove::sys_zk_prove;
pub use stats::sys_zk_get_stats;
pub use verify::sys_zk_verify;
