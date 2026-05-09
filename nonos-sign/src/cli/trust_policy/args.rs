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

use std::path::PathBuf;

use nonos_capsule_sign::algs::AlgId;
use nonos_capsule_sign::error::SignError;

use crate::cli::parse::{parse_alg_path, parse_u64};

pub(super) struct Args {
    pub epoch: u64,
    pub ta_pubs: Vec<(AlgId, PathBuf)>,
    pub valid_from_ms: u64,
    pub valid_until_ms: u64,
    pub out: PathBuf,
}

pub(super) fn parse(args: &[String]) -> Result<Args, SignError> {
    let mut epoch: Option<u64> = None;
    let mut ta_pubs: Vec<(AlgId, PathBuf)> = Vec::new();
    let mut vf: Option<u64> = None;
    let mut vu: u64 = 0;
    let mut out: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        let need = |k: &str| SignError::Usage(format!("mk-trust-policy: {}", k));
        match args[i].as_str() {
            "--epoch" => { epoch = Some(parse_u64(args.get(i + 1).ok_or_else(|| need("--epoch <n>"))?)?); i += 2; }
            "--ta-pub" => {
                let (a, p) = parse_alg_path(args.get(i + 1).ok_or_else(|| need("--ta-pub <a=p>"))?)?;
                ta_pubs.push((a, PathBuf::from(p)));
                i += 2;
            }
            "--valid-from-ms" => { vf = Some(parse_u64(args.get(i + 1).ok_or_else(|| need("--valid-from-ms <n>"))?)?); i += 2; }
            "--valid-until-ms" => { vu = parse_u64(args.get(i + 1).ok_or_else(|| need("--valid-until-ms <n>"))?)?; i += 2; }
            "--out" => { out = Some(PathBuf::from(args.get(i + 1).ok_or_else(|| need("--out <path>"))?)); i += 2; }
            other => return Err(SignError::Usage(format!("mk-trust-policy: unknown `{}`", other))),
        }
    }
    Ok(Args {
        epoch: epoch.ok_or_else(|| SignError::Usage("mk-trust-policy: missing --epoch".into()))?,
        ta_pubs,
        valid_from_ms: vf.ok_or_else(|| SignError::Usage("mk-trust-policy: missing --valid-from-ms".into()))?,
        valid_until_ms: vu,
        out: out.ok_or_else(|| SignError::Usage("mk-trust-policy: missing --out".into()))?,
    })
}
