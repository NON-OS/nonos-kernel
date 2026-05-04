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
fn alloc_error_handler(layout: core::alloc::Layout) -> ! {
    entry::handle_oom(layout)
}

// Microkernel trusted path. Compiled in every build. Every module here
// exists because the boot/init/runtime chain reaches it on the live
// path: entry, scheduler, memory, capability gate, IPC, ELF/capsule
// loader, signing/hash primitives, and the kernel-side mirrors of the
// three real capsules (proof_io, ramfs, keyring).
pub mod arch;
pub mod boot;
pub mod bus;
pub mod capabilities;
pub mod capsule;
pub mod context;
pub mod crypto;
pub mod drivers;
pub mod elf;
pub mod entry;
pub mod fs;
pub mod interrupts;
pub mod ipc;
pub mod kernel_core;
pub mod log;
pub mod mem;
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

// Legacy / migration backlog. Compiled only under `nonos-legacy-tree`,
// off in every microkernel profile. Each subsystem here is on the
// migration list to either land as a real userland capsule under
// `userland/<name>/` or be deleted. No microkernel-path module is
// allowed to depend on this set; cargo check enforces the boundary.
// Historical context lives in `docs/legacy/Cargo.monolithic.toml`.
#[cfg(feature = "nonos-legacy-tree")]
pub mod agents;
#[cfg(feature = "nonos-legacy-tree")]
pub mod apps;
#[cfg(feature = "nonos-legacy-tree")]
pub mod daemon;
#[cfg(feature = "nonos-legacy-tree")]
pub mod display;
#[cfg(feature = "nonos-legacy-tree")]
pub mod graphics;
#[cfg(feature = "nonos-legacy-tree")]
pub mod input;
#[cfg(feature = "nonos-legacy-tree")]
pub mod lang;
#[cfg(feature = "nonos-legacy-tree")]
pub mod locale;
#[cfg(feature = "nonos-legacy-tree")]
pub mod modules;
#[cfg(feature = "nonos-legacy-tree")]
pub mod monitor;
#[cfg(feature = "nonos-legacy-tree")]
pub mod network;
#[cfg(feature = "nonos-legacy-tree")]
pub mod nox;
#[cfg(feature = "nonos-legacy-tree")]
pub mod npkg;
#[cfg(feature = "nonos-legacy-tree")]
pub mod persistence;
#[cfg(feature = "nonos-legacy-tree")]
pub mod runtime;
#[cfg(feature = "nonos-legacy-tree")]
pub mod sdk;
#[cfg(feature = "nonos-legacy-tree")]
pub mod shell;
#[cfg(feature = "nonos-legacy-tree")]
pub mod storage;
#[cfg(feature = "nonos-legacy-tree")]
pub mod tty;
#[cfg(feature = "nonos-legacy-tree")]
pub mod vault;
#[cfg(feature = "nonos-legacy-tree")]
pub mod zk_engine;
#[cfg(feature = "nonos-legacy-tree")]
pub mod zksync;

pub use arch::x86_64::time;
pub use fs as filesystem;
