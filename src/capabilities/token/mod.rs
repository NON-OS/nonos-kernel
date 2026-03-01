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

mod create;
mod material;
mod nonce;
mod revocation;
mod serialization;
mod sign;
mod signing_key;
mod types;
mod validate;
mod verify;

pub use create::{create_token, create_token_with_nonce};
pub use material::{mac64, token_material};
pub use nonce::{current_nonce_counter, default_nonce, reset_nonce_counter};
pub use revocation::{
    clear_revocations, is_revoked, revoke_all_for_owner, revoke_token, revoked_count,
};
pub use serialization::{from_bytes, to_bytes, TOKEN_BINARY_SIZE, TOKEN_VERSION};
pub use sign::sign_token;
pub use signing_key::{has_signing_key, set_signing_key, signing_key};
pub use types::CapabilityToken;
pub use validate::{is_token_not_revoked, is_token_signature_valid, is_token_valid, validate_token_full};
pub use verify::verify_token;
