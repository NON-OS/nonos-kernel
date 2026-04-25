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

pub mod context;
pub mod decrypt_message;
pub mod derive_auth_key;
pub mod derive_capability_key;
pub mod derive_identity_key;
pub mod derive_shared_secret;
pub mod encrypt_message;
pub mod errors;
pub mod get_crypto_context;
pub mod init_global_key;
pub mod ipc_signer;
pub mod ipc_verifier;
pub mod message_signature;

pub use errors::EncryptionError;
