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

// CPU topology at boot.
//
// `boot_cpu_id` identifies the CPU executing kernel bring-up. Format
// is arch-defined: APIC ID on x86_64, MPIDR low bits on aarch64,
// hartid on riscv64. `cpu_count` is the count reported by handoff at
// boot; secondary CPUs are brought up later by `smp::start_aps` (x86),
// PSCI CPU_ON calls (aarch64), or SBI HSM (riscv64).

#[derive(Debug, Clone, Copy)]
pub struct CpuTopology {
    pub boot_cpu_id: u32,
    pub cpu_count: u32,
}
