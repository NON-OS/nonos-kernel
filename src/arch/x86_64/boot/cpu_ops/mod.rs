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

mod tsc;
mod msr;
mod control_regs;
mod xcr;
mod flags;
mod intrinsics;
mod cpuid;
mod tests;

pub use tsc::{rdtsc, rdtscp};
pub use msr::{rdmsr, wrmsr};
pub use control_regs::{read_cr0, write_cr0, read_cr2, read_cr3, write_cr3, read_cr4, write_cr4, read_cr8, write_cr8};
pub use xcr::{read_xcr0, write_xcr0};
pub use flags::{read_rflags, write_rflags};
pub use intrinsics::{cli, sti, hlt, pause, lfence, mfence, sfence, invlpg, halt_loop};
pub use cpuid::{cpuid, cpuid_count};
