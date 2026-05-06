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

use std::path::Path;

use crate::error::CliError;

use super::schema::IndexJson;

pub fn read_index_json(path: &Path) -> Result<IndexJson, CliError> {
    let raw = std::fs::read_to_string(path)?;
    serde_json::from_str(&raw).map_err(|e| CliError::Json(e.to_string()))
}
