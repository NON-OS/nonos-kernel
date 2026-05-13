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

use nonos_capsule_sign::algs::{parse_alg, AlgId};
use nonos_capsule_sign::error::SignError;

pub fn parse_alg_path(s: &str) -> Result<(AlgId, String), SignError> {
    match s.split_once('=') {
        Some((a, p)) => Ok((parse_alg(a)?, p.to_string())),
        None => Err(SignError::Usage(format!("expected alg=path, got `{}`", s))),
    }
}

pub fn parse_u64(s: &str) -> Result<u64, SignError> {
    let stripped = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X"));
    match stripped {
        Some(h) => u64::from_str_radix(h, 16)
            .map_err(|_| SignError::Usage(format!("bad hex u64 `{}`", s))),
        None => s.parse::<u64>().map_err(|_| SignError::Usage(format!("bad u64 `{}`", s))),
    }
}

pub fn parse_hex32(s: &str) -> Result<[u8; 32], SignError> {
    let bytes = decode_hex(s)?;
    if bytes.len() != 32 {
        return Err(SignError::Usage(format!("expected 32-byte hex, got {} bytes", bytes.len())));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn decode_hex(s: &str) -> Result<Vec<u8>, SignError> {
    hex::decode(s).map_err(|e| SignError::InvalidHex(e.to_string()))
}

pub fn parse_version(s: &str) -> Result<(u32, u32, u32), SignError> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 3 {
        return Err(SignError::Usage(format!("version must be maj.min.patch, got `{}`", s)));
    }
    let p = |x: &str| {
        x.parse::<u32>().map_err(|_| SignError::Usage(format!("bad version component `{}`", x)))
    };
    Ok((p(parts[0])?, p(parts[1])?, p(parts[2])?))
}

pub fn require_hybrid_alg_set<T>(label: &str, xs: &[(AlgId, T)]) -> Result<(), SignError> {
    let mut ed25519 = 0usize;
    let mut mldsa65 = 0usize;
    for (alg, _) in xs {
        match alg {
            AlgId::Ed25519 => ed25519 += 1,
            AlgId::MlDsa65 => mldsa65 += 1,
            _ => {
                return Err(SignError::Usage(format!(
                    "{}: production signing requires ed25519 and mldsa65, got {}",
                    label,
                    alg.label()
                )));
            }
        }
    }
    if ed25519 != 1 || mldsa65 != 1 {
        return Err(SignError::Usage(format!(
            "{}: production signing requires exactly one ed25519 and one mldsa65 key",
            label
        )));
    }
    Ok(())
}
