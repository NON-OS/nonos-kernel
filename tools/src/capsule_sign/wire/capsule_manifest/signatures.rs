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
use super::validate;

pub(super) fn encode(sigs: &[PublisherSignatureInput]) -> Result<Vec<u8>, SignError> {
    validate::check_sigs(sigs)?;
    let mut buf = Vec::new();
    buf.push(sigs.len() as u8);
    for s in sigs {
        buf.push(s.alg as u8);
        buf.extend_from_slice(&s.key_id);
        buf.extend_from_slice(&(s.sig.len() as u16).to_be_bytes());
        buf.extend_from_slice(&s.sig);
    }
    Ok(buf)
}
