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

pub mod kill;
pub mod sigaction;
pub mod sigprocmask;
pub mod sigsuspend;

pub use kill::sys_kill;
pub use sigaction::sys_rt_sigaction;
pub use sigprocmask::sys_rt_sigprocmask;
pub use sigsuspend::sys_rt_sigsuspend;
