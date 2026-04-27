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

pub mod api;
pub mod keys;
pub mod policy;
pub mod state;
pub mod types;
pub mod verify;

pub use api::{generate_attestation_report, get_boot_measurements, get_stats, init};
pub use keys::{add_trusted_key, list_trusted_keys, revoke_key};
pub use policy::{get_policy, is_enforcing, set_policy};
pub use types::{
    AttestationReport, BootMeasurements, SecureBootError, SecureBootPolicy, SecureBootResult,
    SecureBootStats, TrustedBootKeys, TrustedKey,
};
pub use verify::{
    is_boot_chain_verified, record_boot_measurements, verify_boot_chain, verify_code_signature,
    verify_kernel,
};
