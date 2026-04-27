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

use crate::hardware::tpm::{nv_write, NvIndex};
use crate::security::anti_rollback::types::{RollbackError, VersionState, NVRAM_VERSION_INDEX};

pub(crate) fn write_to_nvram(state: &VersionState) -> Result<(), RollbackError> {
    let index = NvIndex::new(NVRAM_VERSION_INDEX);
    nv_write(&index, &state.to_bytes()).map_err(|_| RollbackError::NvramWriteFailed)?;
    let hash_index = NvIndex::new(NVRAM_VERSION_INDEX + 1);
    nv_write(&hash_index, &state.compute_hash()).map_err(|_| RollbackError::NvramWriteFailed)?;
    Ok(())
}
