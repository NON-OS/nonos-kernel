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

pub use super::secure_boot_ops::{
    authorize_hash, authorize_signature, get_authorized_hashes, get_revoked_hashes, get_status,
    is_enabled, is_hash_authorized, is_hash_revoked, is_setup_mode, revoke_hash, revoke_signature,
    verify_binary, verify_hash, verify_with_result,
};
pub use super::secure_boot_status::{SecureBootStatus, VerificationResult};
