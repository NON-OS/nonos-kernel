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

use super::error::DecodeError;
use super::reader::Reader;
use super::strings::bounded_string;
use crate::limits::{MAX_DESCRIPTION, MAX_PUBLISHER};
use crate::types::{ValidationReport, ValidationStatus};

pub(super) fn read(r: &mut Reader<'_>) -> Result<ValidationReport, DecodeError> {
    let status = ValidationStatus::from_u8(r.u8()?);
    let note = bounded_string(r, MAX_DESCRIPTION)?;
    let validator_id = bounded_string(r, MAX_PUBLISHER)?;
    let validated_at_ms = r.u64()?;
    Ok(ValidationReport { status, note, validator_id, validated_at_ms })
}
