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
/// binary's `_start` in CPL=3. The binary issues `write` then `_exit`,
/// at which point the process terminates and the scheduler picks the
/// next runnable thread (or the kernel halts if none remain).
///
/// Off when the `nonos-capsule-proof-io` feature is disabled. The
/// capability check inside `contract::dispatch` reads the calling
/// process's token; the inherited capability set already covers `Read`,
/// `Write`, and `Exit` (see `process::capabilities::presets`), so no
/// mint-site change is needed for this proof.
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
