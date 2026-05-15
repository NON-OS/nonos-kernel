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

//! One per-capsule boot wrapper. Each spawn site in `init::run_init`
//! used to repeat the same match-on-`SpawnError` and lifecycle::register
//! dance. They all collapse onto `boot` here. A failed spawn leaves
//! the capsule's `CapsuleState` in its initial dead state, so any IPC
//! the kernel attempts against it after init still fails closed.

extern crate alloc;

use crate::kernel_core::process_spawn::capsule_spawn::SpawnError;
use crate::services::lifecycle::{self, CapsuleState};
use crate::sys::boot_log;

pub fn boot(
    prefix: &str,
    name: &'static str,
    spawn_fn: fn() -> Result<(), SpawnError>,
    state_fn: fn() -> &'static CapsuleState,
) {
    match spawn_fn() {
        Ok(()) => {
            boot_log::ok(prefix, "capsule spawned");
            lifecycle::register(lifecycle::Capsule { name, state: state_fn() });
        }
        Err(e) => boot_log::error(spawn_error_message(prefix, e).as_str()),
    }
}

/// Grant `cap` to the current pid, yield long enough for the capsule
/// to come up on the run queue, then drive its smoketest. Used from
/// the cfg-gated `nonos-*-smoketest` blocks in `run_init`.
pub fn run_smoketest(cap: u64, run_fn: fn()) {
    if let Some(pid) = crate::process::current_pid() {
        let _ = crate::process::caps::grant(pid, cap);
    }
    for _ in 0..200 {
        crate::sched::yield_now();
    }
    run_fn();
}

fn spawn_error_message(prefix: &str, err: SpawnError) -> alloc::string::String {
    let suffix = match err {
        SpawnError::FeatureDisabled => "capsule binary not embedded (feature off)",
        SpawnError::ElfLoad => "capsule ELF load failed",
        SpawnError::ProcessCreation => "process creation failed",
        SpawnError::AddressSpace => "address space allocation failed",
        SpawnError::EndpointCollision => "service endpoint registration failed",
        SpawnError::NonosIdCertRejected(e) => {
            return alloc::format!("{}: NØNOS ID certificate rejected by trust anchor ({:?})", prefix, e);
        }
        SpawnError::ManifestRejected(e) => {
            return alloc::format!("{}: capsule manifest rejected (signature/hash/caps/target) ({:?})", prefix, e);
        }
    };
    alloc::format!("{}: {}", prefix, suffix)
}
