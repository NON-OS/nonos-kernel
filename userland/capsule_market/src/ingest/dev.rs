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

//! Dev-fixture ingest. Skips the signature step and labels the
//! resulting state as not signature-verified, so the
//! install-readiness evaluator refuses every entry the fixture
//! serves. The whole module is compiled out when the `dev-fixture`
//! feature is off; production builds never link this path.

use super::error::IngestError;
use super::load::Verified;

pub fn load_unsigned(blob: &[u8]) -> Result<Verified, IngestError> {
    let decoded =
        nonos_marketplace_abi::decode_index(blob).map_err(|_| IngestError::Malformed)?;
    Ok(Verified { index: decoded.index, signature_verified: false })
}
