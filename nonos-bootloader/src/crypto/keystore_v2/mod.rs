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

mod api;
mod store;
mod types;
mod util;
mod verify;

pub use api::{get_build_timestamp, get_key_fingerprint, get_key_id, init_production_keystore, KEYSTORE_V2};
pub use store::KeystoreV2;
pub use types::{KeyType, KeyValidationResult, TrustedKey, DS_KEY_ROTATION, MAX_TRUSTED_KEYS};
pub use util::constant_time_eq;
