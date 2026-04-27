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

use super::params_deserialize::deserialize_params;
use super::params_serialize::serialize_params;
use crate::zk_engine::setup::params::SetupParameters;
use crate::zk_engine::ZKError;
use alloc::vec::Vec;

pub(crate) fn load_from_storage(path: &str) -> Result<SetupParameters, ZKError> {
    use crate::fs::nonos_filesystem::NonosFilesystem;

    let fs = NonosFilesystem::new();
    let data = fs.read_file(path).map_err(|_| ZKError::TrustedSetupNotFound)?;

    if data.len() < 16 {
        return Err(ZKError::InvalidFormat);
    }
    if &data[0..4] != b"NZKS" {
        return Err(ZKError::InvalidFormat);
    }

    let version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    if version != 1 {
        return Err(ZKError::InvalidFormat);
    }

    deserialize_params(&data[8..])
}

pub(crate) fn save_to_storage(path: &str, params: &SetupParameters) -> Result<(), ZKError> {
    use crate::fs::nonos_filesystem::NonosFilesystem;

    let mut data = Vec::new();
    data.extend_from_slice(b"NZKS");
    data.extend_from_slice(&1u32.to_le_bytes());
    serialize_params(params, &mut data);

    let fs = NonosFilesystem::new();
    fs.create_file(path, &data).map_err(|_| ZKError::SetupError)?;
    Ok(())
}
