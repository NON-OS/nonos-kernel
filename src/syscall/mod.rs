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

extern crate alloc;

pub mod aio;
pub mod bpf;
pub mod caps;
pub mod contract;
pub mod dispatch;
pub mod entry;
#[cfg(feature = "nonos-experimental-syscalls")]
pub mod eventfd;
pub mod extended;
pub mod fanotify;
// Framebuffer surface syscalls. The microkernel does not expose a
// graphics surface; capsules talk to a future `display` capsule via
// IPC. Off in microkernel; the router falls through to ENOSYS.
#[cfg(feature = "nonos-legacy-tree")]
pub mod graphics_surface;
pub mod handler;
#[cfg(feature = "nonos-experimental-syscalls")]
pub mod inotify;
#[cfg(feature = "nonos-experimental-syscalls")]
pub mod io_uring;
#[cfg(feature = "nonos-experimental-syscalls")]
pub mod kcmp;
// Linux-shaped add_key/request_key/keyctl over an in-kernel BTreeMap.
// The live keyring authority is the userland capsule
// (`crate::security::keyring_capsule`); this module exists only so
// legacy callers that still issue the Linux syscalls land somewhere
// instead of returning ENOSYS at the gate. Off in every production
// profile; legacy/dev-only.
#[cfg(feature = "nonos-syscall-keyring")]
pub mod keyring;
#[cfg(feature = "nonos-experimental-syscalls")]
pub mod landlock;
#[cfg(feature = "nonos-experimental-syscalls")]
pub mod memfd;
pub mod microkernel;
pub mod mqueue;
pub mod namespace;
pub mod numbers;
#[cfg(feature = "nonos-experimental-syscalls")]
pub mod perf_event;
#[cfg(feature = "nonos-experimental-syscalls")]
pub mod pidfd;
pub mod pkey;
pub mod process_vm;
pub mod ptrace;
pub mod robust_futex;
pub mod rseq;
pub mod seccomp;
#[cfg(feature = "nonos-experimental-syscalls")]
pub mod signalfd;
pub mod signals;
pub mod splice;
#[cfg(feature = "nonos-experimental-syscalls")]
pub mod statx;
#[cfg(feature = "nonos-experimental-syscalls")]
pub mod timerfd;
pub mod tls;
pub mod types;
#[cfg(feature = "nonos-experimental-syscalls")]
pub mod userfaultfd;
pub mod validation;
pub mod vdso;
pub mod xattr;

#[cfg(test)]
mod tests;

pub use caps as capabilities;
pub use caps::current_caps;
pub use contract::{dispatch as contract_dispatch, Capability, SyscallArgs};
pub use entry::{handle_interrupt, handle_syscall};
pub use numbers::SyscallNumber;
pub use types::{errno, errnos, SyscallResult};
