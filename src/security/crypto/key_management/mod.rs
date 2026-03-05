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


pub mod types;
pub mod errors;
pub mod entry;
pub mod audit;
pub mod store;
pub mod ops;
pub mod rotation;
pub mod derivation;
pub mod deletion;
pub mod query;

pub use types::{KeyType, KeyUsage};
pub use errors::{KeyError, KeyResult};
pub use entry::KeyEntry;
pub use audit::{KeyOperation, KeyAuditEntry};
pub use store::{init, KeyStore, KEY_STORE};
pub use ops::{generate_key, import_key, use_key, export_key};
pub use rotation::rotate_key;
pub use derivation::derive_key;
pub use deletion::{delete_key, delete_all_keys};
pub use query::{KeyInfo, get_key_info, list_keys, list_keys_by_owner, find_key_by_fingerprint, key_count, active_key_count};
