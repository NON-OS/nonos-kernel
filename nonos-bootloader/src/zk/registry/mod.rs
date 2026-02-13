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

mod derive;
mod keys;
mod lookup;
mod parse;
mod store;
mod types;

pub use derive::{derive_circuit_key, verify_circuit_key_derivation};
#[cfg(feature = "zk-groth16")]
pub use keys::{
    compute_vk_fingerprint, verify_vk_fingerprint, CORE_CIRCUITS, ENTRIES,
    ENTRIES_WITH_FINGERPRINT, PROGRAM_HASH_BOOT_AUTHORITY, PROGRAM_HASH_RECOVERY_KEY,
    PROGRAM_HASH_UPDATE_AUTHORITY, VK_BOOT_AUTHORITY_BLS12_381_GROTH16,
    VK_FINGERPRINT_BOOT_AUTHORITY, VK_FINGERPRINT_RECOVERY_KEY, VK_FINGERPRINT_UPDATE_AUTHORITY,
    VK_RECOVERY_KEY_BLS12_381_GROTH16, VK_UPDATE_AUTHORITY_BLS12_381_GROTH16,
};

#[cfg(feature = "zk-groth16")]
pub use lookup::{
    circuits_with_permission, has_permission, lookup, lookup_circuit, lookup_verified, LookupError,
};

pub use parse::parse_circuit_section;
pub use store::DynamicCircuitStore;
pub use types::{
    CircuitCategory, CircuitEntry, CircuitPermission, CircuitSectionEntry, CircuitSectionHeader,
    DynamicCircuitEntry, CIRCUIT_SECTION_MAGIC,
};
