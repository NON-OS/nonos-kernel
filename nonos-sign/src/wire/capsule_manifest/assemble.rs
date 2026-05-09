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

use crate::error::SignError;

use super::inputs::PublisherSignatureInput;
use super::signatures;

pub fn assemble(
    signed_region: &[u8],
    sigs: &[PublisherSignatureInput],
) -> Result<Vec<u8>, SignError> {
    let trailer = signatures::encode(sigs)?;
    let mut out = Vec::with_capacity(signed_region.len() + trailer.len());
    out.extend_from_slice(signed_region);
    out.extend_from_slice(&trailer);
    Ok(out)
}
