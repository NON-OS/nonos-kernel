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

pub mod capsule;
pub mod loader;
mod verify;

pub use crate::crypto::sig::{verify_signature_full, CapsuleMetadata, KeyId, VerifyError};
pub use capsule::CapsuleStatus;
pub use loader::load_validated_capsule;
pub use verify::{validate_capsule, verify_ed25519_signature};
