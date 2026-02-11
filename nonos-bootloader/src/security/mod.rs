// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

pub mod anti_rollback;
pub mod attestation;
mod check;
mod crypto;
mod enforce;
mod init;
mod tpm;
mod types;
mod verify;

pub use crypto::{blake3_selftest, ed25519_selftest, run_all_selftests};
pub use init::{assess_security_posture, initialize_security_subsystem};
pub use tpm::{extend_pcr_measurement, measure_boot_components, pcr};
pub use types::SecurityContext;
pub use verify::{verify_kernel_signature_advanced, verify_signature};

pub use check::{
    check_hardware_rng, check_measured_boot, check_platform_key, check_secure_boot,
    check_signature_db,
};

pub use enforce::{
    detect_secure_boot_bypass, enforce_security_policy, extend_boot_measurements,
    verify_kernel_version, verify_secure_boot_chain, EnforcementResult, SecurityPolicy,
};
