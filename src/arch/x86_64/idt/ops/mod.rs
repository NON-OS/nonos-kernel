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

mod init;
mod handlers;
mod pic;
mod interrupt;
mod stats;

pub use init::{init, is_initialized};
pub use handlers::{register_irq_handler, unregister_irq_handler, register_syscall_handler, register_handler};
pub use pic::{remap_pic, disable_pic, set_pic_masks, get_pic_masks};
pub use interrupt::{enable, disable, are_enabled, without_interrupts};
pub use stats::{IdtStats, get_stats, get_vector_count};
