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

pub mod firmware;
pub mod secure_boot;

pub use secure_boot::{
    add_trusted_key, generate_attestation_report, get_boot_measurements, get_policy,
    get_stats as secure_boot_stats, init as secure_boot_init, is_boot_chain_verified, is_enforcing,
    list_trusted_keys, record_boot_measurements, revoke_key, set_policy, verify_boot_chain,
    verify_code_signature, verify_kernel, AttestationReport, BootMeasurements, SecureBootError,
    SecureBootPolicy, SecureBootResult, SecureBootStats, TrustedBootKeys, TrustedKey,
};

pub use firmware::{init as firmware_init, FirmwareDB};
