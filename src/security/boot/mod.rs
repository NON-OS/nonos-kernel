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

pub mod secure_boot;
pub mod firmware;

pub use secure_boot::{
    init as secure_boot_init, set_policy, get_policy, is_enforcing,
    verify_code_signature, verify_kernel, record_boot_measurements, verify_boot_chain,
    is_boot_chain_verified, add_trusted_key, revoke_key, list_trusted_keys,
    get_boot_measurements, generate_attestation_report, get_stats as secure_boot_stats,
    BootMeasurements, TrustedBootKeys, TrustedKey, SecureBootPolicy, SecureBootError,
    SecureBootResult, AttestationReport, SecureBootStats,
};

pub use firmware::{
    init as firmware_init,
    FirmwareDB,
};
