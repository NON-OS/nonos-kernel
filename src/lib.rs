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

#![no_std]
#![cfg_attr(not(feature = "std"), feature(alloc_error_handler))]
#![feature(abi_x86_interrupt)]
#![feature(c_variadic)]
#![feature(thread_local)]
#![allow(unsafe_op_in_unsafe_fn)]
#![allow(unexpected_cfgs)]

#[macro_use]
extern crate alloc;

#[cfg(not(feature = "std"))]
#[alloc_error_handler]
fn alloc_error_handler(layout: core::alloc::Layout) -> ! { entry::handle_oom(layout) }

pub mod agents; pub mod apps; pub mod arch; pub mod boot; pub mod bus; pub mod capabilities;
pub mod context; pub mod crypto; pub mod daemon; pub mod display; pub mod drivers; pub mod elf;
pub mod entry; pub mod fs; pub mod graphics; pub mod input; pub mod interrupts; pub mod ipc;
pub mod kernel_core; pub mod kernel_selftest; pub mod lang; pub mod libc; pub mod locale; pub mod log;
pub mod mem; pub mod memory; pub mod modules; pub mod monitor; pub mod network; pub mod nox; pub mod npkg;
pub mod persistence; pub mod process; pub mod runtime; pub mod sched; pub mod sdk;
pub mod security; pub mod services; pub mod shell; pub mod smp; pub mod storage; pub mod sys;
pub mod syscall; pub mod test; pub mod tty; pub mod ui; pub mod usercopy; pub mod userspace; pub mod vault;
pub mod zk_engine; pub mod zksync;

pub use arch::x86_64::time as time; pub use fs as filesystem;
