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

use super::embed::{PROOF_IO_ELF, PROOF_IO_PATH};

/// Run the proof_io capsule once. The current process's address space
/// is replaced by the proof binary and control transfers to the
/// binary's `_start` in CPL=3. The binary emits one MkDebug marker
/// then MkExit, at which point the process terminates and the
/// scheduler picks the next runnable thread (or the kernel halts if
/// none remain). There is no `write` call, no fd, and no Linux-shape
/// syscall on this path.
///
/// Off when the `nonos-capsule-proof-io` feature is disabled.
///
/// Capability gating: MkExit and MkYield only require a valid token;
/// MkDebug requires `crate::capabilities::Capability::Debug`, which a
/// production kernel does not grant. Smoketest builds OR `Debug` into
/// every spawned capsule via the spawn pipeline. This launch path
/// uses `exec_process` and inherits init's caps_bits; a smoketest
/// build that wants the `[proof_io]` marker on serial must mirror the
/// grant on the inherited side. The `nonos-capsule-proof-io` ELF
/// itself never escalates.
pub fn launch() {
    if PROOF_IO_ELF.is_empty() {
        return;
    }
    crate::sys::serial::println(b"[NONOS] proof_io: launching from /capsules/proof_io");
    let _ = crate::process::exec_process(PROOF_IO_PATH, &[], &[]);
    // exec_process is `-> Result<Infallible, _>` on success; reaching
    // this point means the load failed before the user-mode transition.
    crate::sys::serial::println(b"[NONOS] proof_io: launch returned (load failure)");
}
