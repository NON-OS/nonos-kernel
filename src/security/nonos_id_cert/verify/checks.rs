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

use crate::security::nonos_trust_anchor::NonosTrustAnchorPolicy;

use super::super::error::IdCertVerifyError;
use super::super::schema::NonosIdCertificate;

pub(super) fn run(
    cert: &NonosIdCertificate,
    policy: &NonosTrustAnchorPolicy,
    now_ms: Option<u64>,
) -> Result<(), IdCertVerifyError> {
    if cert.trust_anchor_epoch < policy.trust_anchor_epoch {
        return Err(IdCertVerifyError::EpochStale);
    }
    if policy.cert_serial_revoked(cert.cert_serial) {
        return Err(IdCertVerifyError::Revoked);
    }
    if policy.nonos_id_revoked(&cert.nonos_id) {
        return Err(IdCertVerifyError::NonosIdRevoked);
    }
    if let Some(ts) = now_ms {
        if ts < cert.valid_from_ms {
            return Err(IdCertVerifyError::NotYetValid);
        }
        if ts >= cert.valid_until_ms {
            return Err(IdCertVerifyError::Expired);
        }
    }
    Ok(())
}
