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

use nonos_marketplace_abi::{ValidationReport, ValidationStatus};

use crate::error::CliError;

use super::schema::ValidationJson;

pub(super) fn to_validation(v: &ValidationJson) -> Result<ValidationReport, CliError> {
    let status = match v.status.as_str() {
        "unknown" => ValidationStatus::Unknown,
        "pending" => ValidationStatus::Pending,
        "validated" => ValidationStatus::Validated,
        "rejected" => ValidationStatus::Rejected,
        other => {
            return Err(CliError::UnknownEnum {
                field: "validation.status",
                value: other.to_string(),
            })
        }
    };
    Ok(ValidationReport {
        status,
        note: v.note.clone(),
        validator_id: v.validator_id.clone(),
        validated_at_ms: v.validated_at_ms,
    })
}
