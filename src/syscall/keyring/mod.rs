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
mod key;
mod key_ops;
mod store;
mod special;
mod search;
mod add_key;
mod request_key;
mod keyctl;
mod keyctl_ops;
mod keyctl_ops2;

pub use types::{KeySerial, KeyType, KEY_SPEC_THREAD_KEYRING, KEY_SPEC_PROCESS_KEYRING};
pub use types::{KEY_SPEC_SESSION_KEYRING, KEY_SPEC_USER_KEYRING};
pub use types::{KEYCTL_GET_KEYRING_ID, KEYCTL_READ, KEYCTL_UPDATE, KEYCTL_LINK, KEYCTL_UNLINK};
pub use key::Key;
pub use store::{allocate_key_serial, store_key, get_key, remove_key, key_count};
pub use special::resolve_special_keyring;
pub use search::{search_keyring, search_keyring_recursive, list_keyring_keys};
pub use add_key::handle_add_key;
pub use request_key::handle_request_key;
pub use keyctl::handle_keyctl;
