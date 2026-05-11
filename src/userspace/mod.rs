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

// Microkernel runtime: init bootstrap and the proof_io capsule launcher.
//
// Only kernel-side glue for *real* userland capsules is allowed to live
// under this path. Real capsule binaries live under `userland/<name>/`
// and are spawned through their own kernel-side mirrors
// (`src/fs/ramfs_capsule`, `src/security/keyring_capsule`,
// `src/userspace/capsule_proof_io`).
//
// Kernel-resident `*_engine` wrappers live under `src/services/` and
// are not real userspace. The CI grep gate in
// `nonos-ci/run-static-checks.sh` rejects any new `src/userspace/*_service`
// directory.

pub mod capsule_proof_io;
pub mod capsule_compositor;
pub mod capsule_wallpaper;
pub mod init;

pub use init::run_init;

#[cfg(test)]
pub mod tests;
