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

pub mod abi;
pub mod context;
pub mod cpu;
#[cfg(any(target_arch = "aarch64", target_arch = "riscv64"))]
pub mod fdt;
pub mod halt;
pub mod trap;

#[cfg(target_arch = "x86_64")]
pub mod nonos_boot;

#[cfg(target_arch = "x86_64")]
pub mod x86_64;

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

#[cfg(target_arch = "riscv64")]
pub mod riscv64;

#[cfg(test)]
mod tests;

pub use abi::ArchOps;
pub use cpu::{cpu_yield, disable_interrupts, enable_interrupts, get_cpu_id, idle_cpu};
#[cfg(target_arch = "x86_64")]
pub use cpu::init_cpu_features;
pub use halt::halt_loop;

// Active architecture backend. Generic kernel code reaches leaf
// primitives via `<Arch as ArchOps>::method()`.
#[cfg(target_arch = "x86_64")]
pub type Arch = x86_64::abi::X86_64;
#[cfg(target_arch = "aarch64")]
pub type Arch = aarch64::abi::Aarch64;
#[cfg(target_arch = "riscv64")]
pub type Arch = riscv64::abi::Riscv64;

#[cfg(target_arch = "x86_64")]
pub use nonos_boot as boot;

#[cfg(target_arch = "x86_64")]
pub use x86_64::*;

#[cfg(target_arch = "aarch64")]
pub use aarch64::*;

#[cfg(target_arch = "riscv64")]
pub use riscv64::*;
