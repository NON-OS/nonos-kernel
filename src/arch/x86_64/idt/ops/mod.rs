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

mod handlers;
mod init;
pub mod init_exceptions;
pub mod init_irqs;
mod interrupt;
mod pic;
mod stats;

pub use handlers::register_handler;
pub use handlers::{register_irq_handler, register_syscall_handler, unregister_irq_handler};
pub use init::{init, is_initialized};
pub use init_exceptions::setup_exceptions;
pub use init_irqs::setup_irqs;
pub use interrupt::{are_enabled, disable, enable, without_interrupts};
pub use pic::{disable_pic, get_pic_masks, remap_pic, set_pic_masks};
pub use stats::{get_stats, get_vector_count, IdtStats};
