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

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use crate::algs::AlgId;
use crate::error::SignError;

use super::format::{MAGIC_PUB, MAGIC_SEED};

pub fn write_seed(path: &Path, alg: AlgId, bytes: &[u8]) -> Result<(), SignError> {
    let blob = encode(MAGIC_SEED, alg, bytes);
    fs::write(path, &blob)?;
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    fs::set_permissions(path, perms)?;
    Ok(())
}

pub fn write_pub(path: &Path, alg: AlgId, bytes: &[u8]) -> Result<(), SignError> {
    let blob = encode(MAGIC_PUB, alg, bytes);
    fs::write(path, &blob)?;
    Ok(())
}

pub fn write_keypair(prefix: &Path, alg: AlgId, seed: &[u8], pubkey: &[u8]) -> Result<(), SignError> {
    let base = prefix.as_os_str().to_string_lossy().into_owned();
    write_seed(&PathBuf::from(format!("{}.seed", base)), alg, seed)?;
    write_pub(&PathBuf::from(format!("{}.pub", base)), alg, pubkey)?;
    Ok(())
}

fn encode(magic: &[u8; 8], alg: AlgId, bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(11 + bytes.len());
    out.extend_from_slice(magic);
    out.push(alg as u8);
    out.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    out.extend_from_slice(bytes);
    out
}
