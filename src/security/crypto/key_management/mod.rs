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

pub mod audit;
pub mod deletion;
pub mod derivation;
pub mod entry;
pub mod errors;
pub mod ops;
pub mod query;
pub mod rotation;
pub mod store;
pub mod types;

pub use audit::{KeyAuditEntry, KeyOperation};
pub use deletion::{delete_all_keys, delete_key};
pub use derivation::derive_key;
pub use entry::KeyEntry;
pub use errors::{KeyError, KeyResult};
pub use ops::{export_key, generate_key, import_key, use_key};
pub use query::{
    active_key_count, find_key_by_fingerprint, get_key_info, key_count, list_keys,
    list_keys_by_owner, KeyInfo,
};
pub use rotation::rotate_key;
pub use store::{init, KeyStore, KEY_STORE};
pub use types::{KeyType, KeyUsage};
