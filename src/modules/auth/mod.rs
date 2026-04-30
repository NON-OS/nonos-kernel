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

// Module signature verification, attestation, and the auth context model.
//
// A separate `AuthContext` type lives in `src/ipc/auth.rs` for IPC
// authentication — different domain, intentionally separate. If the name
// collision starts causing real confusion, rename one. It hasn't yet.

extern crate alloc;

pub mod constants;
pub mod error;
pub mod types;
pub mod verification;

#[cfg(test)]
#[cfg(not(feature = "std"))]
#[cfg(test)]
mod tests;

pub use constants::*;
pub use error::{AuthError, AuthResult};
pub use types::{AuthContext, AuthMethod};
pub use verification::{authenticate_module, erase_auth_context, verify_signature};
