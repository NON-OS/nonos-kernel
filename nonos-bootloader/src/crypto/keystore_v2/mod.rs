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
mod store_add;
mod store_core;
mod store_query;
mod store_revoke;
mod types_consts;
mod types_key;
mod types_result;
mod types_trusted_key;
mod util;
mod verify_multisig;
mod verify_single;

pub use api::{get_keystore_fingerprint, init_production_keystore, KEYSTORE_V2};
pub use store_core::KeystoreV2;
pub use types_consts::{DS_KEY_ROTATION, MAX_TRUSTED_KEYS};
pub use types_key::KeyType;
pub use types_result::KeyValidationResult;
pub use types_trusted_key::TrustedKey;
pub use util::constant_time_eq;
