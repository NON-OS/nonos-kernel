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

use spin::Mutex;

use super::store::KeystoreV2;
use super::types::{KeyType, TrustedKey};

pub static KEYSTORE_V2: Mutex<KeystoreV2> = Mutex::new(KeystoreV2::new());

include!(concat!(env!("OUT_DIR"), "/keys_generated.rs"));

pub fn get_key_fingerprint() -> &'static str {
    KEY_FINGERPRINT
}

pub fn get_key_id() -> &'static [u8; 32] {
    &NONOS_KEY_ID
}

pub fn get_build_timestamp() -> u64 {
    BUILD_TIMESTAMP
}

pub fn init_production_keystore() -> Result<usize, &'static str> {
    let mut store = KEYSTORE_V2.lock();

    let primary_key = TrustedKey::new(NONOS_PUBLIC_KEY, KEY_VERSION, 0, 0, KeyType::Primary);

    store.add_key(primary_key)?;

    Ok(store.key_count())
}
