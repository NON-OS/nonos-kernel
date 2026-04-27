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

use crate::handoff::CryptoHandoff;

use super::params::HandoffParams;

pub fn build_crypto_handoff(params: &HandoffParams) -> CryptoHandoff {
    CryptoHandoff {
        signature_valid: params.signature_valid,
        secure_boot: params.secure_boot,
        kernel_hash: params.kernel_hash,
        zk_attested: params.zk_result.zk_verified,
        zk_program_hash: params.zk_result.program_hash,
        zk_capsule_commitment: params.zk_result.capsule_commitment,
    }
}
