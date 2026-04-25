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

mod block;
mod input;
mod net;
mod tty;

pub use block::*;
pub use input::*;
pub use net::*;
pub use tty::*;

use super::kobject::{register_kobject, KobjectType};

static mut CLASS_INO: u64 = 100;

pub fn init_class_subsystem() {
    unsafe {
        CLASS_INO = 100;
    }
    block::init_block_class();
    net::init_net_class();
    tty::init_tty_class();
    input::init_input_class();
}

pub fn get_class_ino() -> u64 {
    unsafe { CLASS_INO }
}

pub fn register_class(name: &str) -> u64 {
    register_kobject(name, KobjectType::Class, get_class_ino())
}
