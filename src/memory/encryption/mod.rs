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

mod types;
mod detect;
mod sme;
mod tme;
mod api;
mod error;

pub use types::{MemEncryption, EncryptionCapability, EncryptionStatus};
pub use detect::{detect_encryption_support, get_encryption_mask};
pub use sme::{init_sme, enable_sme, sme_encrypt_page, sme_decrypt_page, get_sme_status};
pub use tme::{init_tme, enable_tme, get_tme_keyid_bits, get_mktme_keyid_partitioning};
pub use api::{init_memory_encryption, is_encryption_enabled, encrypt_region, decrypt_region, get_encryption_stats};
pub use sme::is_page_encrypted;
pub use tme::is_tme_enabled;
pub use error::{MemEncryptionError, MemEncryptionResult};
