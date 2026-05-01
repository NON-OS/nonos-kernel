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

// Cross-architecture measured-boot handoff.
//
// Trust-anchor work depends on these fields being honest. The
// per-arch boot code is responsible for filling them in based on the
// platform measurement source: TPM 2.0 PCRs on x86_64, secure-boot
// chain status on aarch64 platforms that expose it, measured-boot
// quote on riscv64 platforms that have one. A platform with no
// measurement source reports both fields as `false`.

#[derive(Debug, Clone, Copy)]
pub struct Measurement {
    pub secure_boot: bool,
    pub kernel_signature_verified: bool,
}
