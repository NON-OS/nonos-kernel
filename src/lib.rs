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
// Kernel-wide lint exceptions. Keep this list small. These cover
// intentional kernel patterns: page-size arithmetic, static lock/atomic
// initializers, and raw syscall-entry helpers after trap/usercopy checks.
#![allow(clippy::integer_division)]
#![allow(clippy::declare_interior_mutable_const)]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

// NØNOS capsule trust posture mutex. `nonos-production` excludes
// the legacy unverified capsule spawn path; any future
// `nonos-dev-unverified-capsules` would re-enable it. The two
// cannot coexist without weakening the production trust contract.
#[cfg(all(feature = "nonos-production", feature = "nonos-dev-unverified-capsules"))]
compile_error!(
    "nonos-production and nonos-dev-unverified-capsules are mutually exclusive: \
     production builds must not enable the unverified capsule spawn path."
);

#[macro_use]
extern crate alloc;

#[cfg(not(feature = "std"))]
#[alloc_error_handler]
fn alloc_error_handler(layout: core::alloc::Layout) -> ! {
    entry::handle_oom(layout)
}

// Microkernel modules. Every entry is reached on the live boot/init
// path or by a kernel-side capsule mirror.
pub mod arch;
pub mod boot;
pub mod bus;
pub mod capabilities;
pub mod context;
pub mod crypto;
pub mod drivers;
pub mod elf;
pub mod entry;
pub mod fs;
pub mod hardware;
pub mod interrupts;
pub mod ipc;
pub mod kernel_core;
pub mod log;
pub mod memory;
pub mod process;
pub mod sched;
pub mod security;
pub mod services;
pub mod smp;
pub mod sys;
pub mod syscall;
pub mod usercopy;
pub mod userspace;

pub use arch::x86_64::time;
pub use fs as filesystem;
