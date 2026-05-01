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

// Cross-architecture timing handoff.
//
// `fixed_freq_hz` is the frequency of the architecture's invariant
// counter when it has one: invariant TSC on modern x86_64, generic
// timer (CNTFRQ_EL0) on aarch64, mtime on riscv64. A `None` value means
// the bootloader could not establish the frequency; the kernel must
// measure it during clock init.
//
// `unix_epoch_ms` carries the bootloader-observed wall-clock timestamp
// at handoff. Kernel-core wall-clock state is initialized against this
// value plus the elapsed counter delta since handoff.

#[derive(Debug, Clone, Copy)]
pub struct TimingHandoff {
    pub fixed_freq_hz: Option<u64>,
    pub unix_epoch_ms: u64,
}
