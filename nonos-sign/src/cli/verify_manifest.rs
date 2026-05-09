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
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use nonos_capsule_sign::algs::AlgId;
use nonos_capsule_sign::error::SignError;
use nonos_capsule_sign::verify::decode::{
    decode_cert, decode_manifest, decode_trust_anchor_policy,
};
use nonos_capsule_sign::verify::{verify_cert, verify_manifest};

const REQUIRED: &[AlgId] = &[AlgId::Ed25519, AlgId::MlDsa65];

pub fn run(av: &[String]) -> Result<(), SignError> {
    let (mp, cp, pp, now_ms) = parse(av)?;
    let mb = fs::read(&mp)?;
    let cb = fs::read(&cp)?;
    let pb = fs::read(&pp)?;
    let dpol = decode_trust_anchor_policy(&pb)?;
    let dcert = decode_cert(&cb)?;
    verify_cert(&dcert, &cb, &dpol, REQUIRED, Some(now_ms))?;
    let dmf = decode_manifest(&mb)?;
    verify_manifest(&dmf, &mb, &dcert, &cb, &dpol, REQUIRED)?;
    println!("manifest {} verifies under cert {} + policy {}",
        mp.display(), cp.display(), pp.display());
    println!("  namespace              {}", dmf.namespace);
    println!("  version                {}.x.x", dmf.version_major);
    println!("  target_triple          {}", dmf.target_triple);
    println!("  required_caps          0x{:016x}", dmf.required_caps);
    println!("  optional_caps          0x{:016x}", dmf.optional_caps);
    println!("  endpoints              {}", dmf.endpoints.len());
    println!("  publisher signatures   {}", dmf.publisher_signatures.len());
    Ok(())
}

fn parse(av: &[String]) -> Result<(PathBuf, PathBuf, PathBuf, u64), SignError> {
    let (mut mf, mut ce, mut po, mut now) = (None, None, None, None);
    let mut i = 0;
    while i < av.len() {
        let n = |k: &str| SignError::Usage(format!("verify-manifest: {}", k));
        let v = |k: &str| av.get(i + 1).ok_or_else(|| n(k));
        match av[i].as_str() {
            "--manifest" => { mf = Some(PathBuf::from(v("--manifest <path>")?)); i += 2; }
            "--cert" => { ce = Some(PathBuf::from(v("--cert <path>")?)); i += 2; }
            "--policy" => { po = Some(PathBuf::from(v("--policy <path>")?)); i += 2; }
            "--now-ms" => { now = Some(v("--now-ms <n>")?.parse().map_err(|_| n("bad --now-ms"))?); i += 2; }
            other => return Err(n(&format!("unknown `{}`", other))),
        }
    }
    let now_v = now.unwrap_or_else(|| {
        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
    });
    Ok((
        mf.ok_or_else(|| SignError::Usage("verify-manifest: missing --manifest".into()))?,
        ce.ok_or_else(|| SignError::Usage("verify-manifest: missing --cert".into()))?,
        po.ok_or_else(|| SignError::Usage("verify-manifest: missing --policy".into()))?,
        now_v,
    ))
}
