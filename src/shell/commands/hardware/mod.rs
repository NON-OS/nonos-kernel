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

mod pci;
mod cpu;
mod storage;
mod usb;
mod dmesg;

pub use self::pci::cmd_lspci;
pub use self::cpu::cmd_lscpu;
pub use self::storage::cmd_lsblk;
pub use self::usb::cmd_lsusb;
pub use self::dmesg::{cmd_dmesg, cmd_dmesg_with_args};
