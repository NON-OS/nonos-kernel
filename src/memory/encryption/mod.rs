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

mod api;
mod cbit_validate;
mod detect;
mod error;
mod sme;
mod tme;
mod types;
mod walker;

pub use api::{
    decrypt_region, encrypt_region, get_encryption_stats, init_memory_encryption,
    is_encryption_enabled,
};
pub use cbit_validate::validate_c_bit_position;
pub use detect::{detect_encryption_support, get_encryption_mask};
pub use error::{MemEncryptionError, MemEncryptionResult};
pub use sme::is_page_encrypted;
pub use sme::{enable_sme, get_sme_status, init_sme, sme_decrypt_page, sme_encrypt_page};
pub use tme::is_tme_enabled;
pub use tme::{enable_tme, get_mktme_keyid_partitioning, get_tme_keyid_bits, init_tme};
pub use types::{EncryptionCapability, EncryptionStatus, MemEncryption};
pub use walker::apply_cbit_to_kernel_mappings;
