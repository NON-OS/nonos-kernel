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

extern crate alloc;

use crate::security::nonos_id_cert::IdCertVerifyError;

pub(super) fn message(prefix: &str, reason: IdCertVerifyError) -> alloc::string::String {
    let why = match reason {
        IdCertVerifyError::Decode(d) => {
            return alloc::format!("{}: NØNOS ID cert decode failed ({:?})", prefix, d);
        }
        IdCertVerifyError::TrustAnchorPolicy => "policy rejected cert (epoch/revoke/window)",
        IdCertVerifyError::TrustAnchorBadSig(alg) => {
            return alloc::format!("{}: trust-anchor signature on cert is bad ({:?})", prefix, alg,);
        }
        IdCertVerifyError::EpochStale => "cert epoch older than current trust-anchor epoch",
        IdCertVerifyError::Revoked => "cert serial appears on revocation list",
        IdCertVerifyError::NonosIdRevoked => "NØNOS ID appears on revocation list",
        IdCertVerifyError::Expired => "cert validity window has expired",
        IdCertVerifyError::NotYetValid => "cert is not yet valid (clock before valid_from)",
    };
    alloc::format!("{}: NØNOS ID cert rejected ({})", prefix, why)
}
