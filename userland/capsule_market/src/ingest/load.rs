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

//! Verified ingest. Decodes a marketplace index blob, asks the
//! configured verifier whether the operator signature checks,
//! and refuses anything that does not pass. The function never
//! installs anything itself; it returns the validated index and
//! lets the caller commit it to the store on success.

use nonos_marketplace_abi::{decode_index, MarketplaceIndex};

use super::error::IngestError;
use crate::bootstrap_trust;
use crate::verify::{Verdict, Verifier};

pub struct Verified {
    pub index: MarketplaceIndex,
    pub signature_verified: bool,
}

pub fn load_verified<V: Verifier>(
    blob: &[u8],
    verifier: &V,
    last_serial: u64,
) -> Result<Verified, IngestError> {
    let decoded = decode_index(blob).map_err(|_| IngestError::Malformed)?;

    if decoded.index.serial <= last_serial && last_serial != 0 {
        return Err(IngestError::StaleSerial);
    }

    if !bootstrap_trust::is_trusted(&decoded.index.operator_pubkey) {
        return Err(IngestError::UntrustedOperator);
    }

    let verdict = verifier.verify(
        decoded.signed_bytes,
        &decoded.index.index_signature,
        &decoded.index.operator_pubkey,
    );
    if verdict != Verdict::Accepted {
        return Err(IngestError::SignatureRefused);
    }

    Ok(Verified { index: decoded.index, signature_verified: true })
}
