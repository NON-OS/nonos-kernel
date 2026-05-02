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

// Compile-time embed of the userland binary. Requires the userland
// crate to be built first (Makefile target `proof_io`); without that,
// the kernel build with the `nonos-capsule-proof-io` feature on will
// fail at this `include_bytes!` with a clear file-not-found error.
#[cfg(feature = "nonos-capsule-proof-io")]
pub(crate) const PROOF_IO_ELF: &[u8] = include_bytes!(
    "../../../userland/capsule_proof_io/target/x86_64-nonos-user/release/proof_io"
);

// Without the feature the constant is empty; `seed` and `launch`
// observe the empty length and do nothing.
#[cfg(not(feature = "nonos-capsule-proof-io"))]
pub(crate) const PROOF_IO_ELF: &[u8] = &[];

pub(crate) const PROOF_IO_PATH: &str = "/capsules/proof_io";
