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

mod driver;
mod operations;
mod ldisc;
mod n_tty;
mod buffer;
mod ioctl;
mod termios;
pub mod pty;
pub mod console;

pub use driver::{TtyDriver, register_driver, unregister_driver};
pub use operations::{TtyOps, read, write, ioctl, poll};
pub use ldisc::{LineDiscipline, get_ldisc, set_ldisc};
pub use n_tty::NTtyLdisc;
pub use buffer::{TtyBuffer, TtyFlipBuffer};
pub use ioctl::{tty_ioctl, TCGETS, TCSETS, TCSETSW, TCSETSF};
pub use termios::{Termios, Winsize};
pub use console::{console_read, console_write, console_ioctl, console_poll};
