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

// Terminal, session, and control semantics live here.
//
// Low-level device primitives (uart, serial, console drivers) belong under
// their specific driver modules — not in a parallel terminal subsystem.
// An old `src/drivers/tty` shell that confused those layers was removed.

mod buffer;
pub mod console;
mod driver;
mod ioctl;
mod ldisc;
mod n_tty;
mod operations;
pub mod pty;
mod termios;

pub use buffer::*;
pub use console::*;
pub use driver::*;
pub use ioctl::*;
pub use ldisc::*;
pub use n_tty::*;
pub use operations::*;
pub use termios::*;
