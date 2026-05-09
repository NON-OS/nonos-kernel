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
use std::path::Path;

use crate::algs::AlgId;
use crate::error::SignError;

use super::format::{MAGIC_PUB, MAGIC_SEED};
use super::types::AlgKeyMaterial;

pub fn read_seed(path: &Path) -> Result<AlgKeyMaterial, SignError> {
    let raw = fs::read(path)?;
    parse(&raw, MAGIC_SEED, "seed", |alg| alg.seed_len())
}

pub fn read_pub(path: &Path) -> Result<AlgKeyMaterial, SignError> {
    let raw = fs::read(path)?;
    parse(&raw, MAGIC_PUB, "pub", |alg| alg.pubkey_len())
}

fn parse(
    raw: &[u8],
    magic: &[u8; 8],
    label: &'static str,
    expected: impl Fn(AlgId) -> usize,
) -> Result<AlgKeyMaterial, SignError> {
    if raw.len() < 11 || &raw[..8] != magic {
        return Err(SignError::KeyFileShape(format!("missing {} magic", label)));
    }
    let alg = AlgId::from_u8(raw[8])?;
    let len = u16::from_be_bytes([raw[9], raw[10]]) as usize;
    if raw.len() != 11 + len {
        return Err(SignError::KeyFileShape(format!("{} length mismatch", label)));
    }
    let want = expected(alg);
    if len != want {
        return Err(SignError::KeyFileShape(format!(
            "{} {} length {} != {}",
            alg.label(),
            label,
            len,
            want
        )));
    }
    Ok(AlgKeyMaterial { alg, bytes: raw[11..].to_vec() })
}
