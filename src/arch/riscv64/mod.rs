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

pub mod boot;
pub mod cpu;
pub mod interrupts;
pub mod mmu;
pub mod plic;
pub mod sbi;
pub mod security;
pub mod timer;
pub mod uart;

pub use boot::init;
pub use cpu::{cpu_id, halt, enable_interrupts, disable_interrupts};
pub use interrupts::TrapFrame;
pub use mmu::{init_mmu, PageTable, map_page, unmap_page};
pub use plic::{init_plic, enable_irq, Plic};
pub use sbi::{console_putchar, console_getchar, set_timer, shutdown};
pub use timer::{init_timer, current_time_ns, read_time};
pub use uart::{init_uart, putc, puts};

pub const PAGE_SIZE: usize = 4096;
pub const STACK_SIZE: usize = 32768;
