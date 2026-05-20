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
    match err {
        SpawnError::FeatureDisabled => {
            alloc::format!("{}: capsule binary not embedded (feature off)", prefix)
        }
        SpawnError::ElfLoad => alloc::format!("{}: capsule ELF load failed", prefix),
        SpawnError::ProcessCreation => alloc::format!("{}: process creation failed", prefix),
        SpawnError::AddressSpace => {
            alloc::format!("{}: address space allocation failed", prefix)
        }
        SpawnError::EndpointCollision => {
            alloc::format!("{}: service endpoint registration failed", prefix)
        }
        SpawnError::NonosIdCertRejected(reason) => {
            let why = match reason {
                crate::security::nonos_id_cert::IdCertVerifyError::Decode(d) => {
                    return alloc::format!(
                        "{}: NØNOS ID cert decode failed ({:?})",
                        prefix, d,
                    );
                }
                crate::security::nonos_id_cert::IdCertVerifyError::TrustAnchorPolicy => {
                    "policy rejected cert (epoch/revoke/window)"
                }
                crate::security::nonos_id_cert::IdCertVerifyError::TrustAnchorBadSig(alg) => {
                    return alloc::format!(
                        "{}: trust-anchor signature on cert is bad ({:?})",
                        prefix, alg,
                    );
                }
                crate::security::nonos_id_cert::IdCertVerifyError::EpochStale => {
                    "cert epoch older than current trust-anchor epoch"
                }
                crate::security::nonos_id_cert::IdCertVerifyError::Revoked => {
                    "cert serial appears on revocation list"
                }
                crate::security::nonos_id_cert::IdCertVerifyError::NonosIdRevoked => {
                    "NØNOS ID appears on revocation list"
                }
                crate::security::nonos_id_cert::IdCertVerifyError::Expired => {
                    "cert validity window has expired"
                }
                crate::security::nonos_id_cert::IdCertVerifyError::NotYetValid => {
                    "cert is not yet valid (clock before valid_from)"
                }
            };
            alloc::format!("{}: NØNOS ID cert rejected ({})", prefix, why)
        }
        SpawnError::ManifestRejected(reason) => {
            let why = match reason {
                crate::security::capsule_manifest::ManifestVerifyError::Decode(d) => {
                    return alloc::format!(
                        "{}: capsule manifest decode failed ({:?})",
                        prefix, d,
                    );
                }
                crate::security::capsule_manifest::ManifestVerifyError::NonosIdCertIdMismatch => {
                    "manifest references a different cert than the one provided"
                }
                crate::security::capsule_manifest::ManifestVerifyError::NamespaceOutsideCert => {
                    "manifest namespace is not authorised by the cert's namespace globs"
                }
                crate::security::capsule_manifest::ManifestVerifyError::CapsExceedCeiling => {
                    "requested capability mask exceeds the cert's caps ceiling"
                }
                crate::security::capsule_manifest::ManifestVerifyError::PublisherPolicy => {
                    "publisher signature policy not satisfied"
                }
                crate::security::capsule_manifest::ManifestVerifyError::PublisherKeyRevoked => {
                    "publisher key appears on the revocation list"
                }
                crate::security::capsule_manifest::ManifestVerifyError::PublisherBadSig(alg) => {
                    return alloc::format!(
                        "{}: publisher signature on manifest is bad ({:?})",
                        prefix, alg,
                    );
                }
                crate::security::capsule_manifest::ManifestVerifyError::PayloadHashMismatch => {
                    "embedded ELF hash differs from manifest expected hash (rebuild + re-sign)"
                }
                crate::security::capsule_manifest::ManifestVerifyError::TargetTripleMismatch => {
                    "target triple in manifest does not match the running capsule binary"
                }
                crate::security::capsule_manifest::ManifestVerifyError::EndpointDeclDrift => {
                    "endpoint declarations drifted between manifest and spawn spec"
                }
                crate::security::capsule_manifest::ManifestVerifyError::GrantOutsideManifest => {
                    "broker grant lives outside the manifest's allowed surface"
                }
            };
            alloc::format!("{}: capsule manifest rejected ({})", prefix, why)
        }
    }
}
