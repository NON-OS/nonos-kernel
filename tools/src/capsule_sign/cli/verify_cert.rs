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
use nonos_capsule_sign::verify::decode::{decode_cert, decode_trust_anchor_policy};
use nonos_capsule_sign::verify::verify_cert;

const REQUIRED: &[AlgId] = &[AlgId::Ed25519, AlgId::MlDsa65];

pub fn run(av: &[String]) -> Result<(), SignError> {
    let (cert_p, pol_p, now_ms) = parse(av)?;
    let cert_bytes = fs::read(&cert_p)?;
    let pol_bytes = fs::read(&pol_p)?;
    let dpol = decode_trust_anchor_policy(&pol_bytes)?;
    let dcert = decode_cert(&cert_bytes)?;
    verify_cert(&dcert, &cert_bytes, &dpol, REQUIRED, Some(now_ms))?;
    println!("cert {} verifies under policy {} at now_ms={}",
        cert_p.display(), pol_p.display(), now_ms);
    println!("  cert_serial            {}", dcert.cert_serial);
    println!("  trust_anchor_epoch     {}", dcert.trust_anchor_epoch);
    println!("  publisher keys         {}", dcert.publisher_keys.len());
    println!("  trust-anchor sigs      {}", dcert.trust_anchor_signatures.len());
    Ok(())
}

fn parse(av: &[String]) -> Result<(PathBuf, PathBuf, u64), SignError> {
    let mut cert: Option<PathBuf> = None;
    let mut policy: Option<PathBuf> = None;
    let mut now_ms: Option<u64> = None;
    let mut i = 0;
    while i < av.len() {
        let n = |k: &str| SignError::Usage(format!("verify-cert: {}", k));
        let v = |k: &str| av.get(i + 1).ok_or_else(|| n(k));
        match av[i].as_str() {
            "--cert" => { cert = Some(PathBuf::from(v("--cert <path>")?)); i += 2; }
            "--policy" => { policy = Some(PathBuf::from(v("--policy <path>")?)); i += 2; }
            "--now-ms" => { now_ms = Some(v("--now-ms <n>")?.parse().map_err(|_| n("bad --now-ms"))?); i += 2; }
            other => return Err(n(&format!("unknown `{}`", other))),
        }
    }
    let now = now_ms.unwrap_or_else(|| {
        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
    });
    Ok((
        cert.ok_or_else(|| SignError::Usage("verify-cert: missing --cert".into()))?,
        policy.ok_or_else(|| SignError::Usage("verify-cert: missing --policy".into()))?,
        now,
    ))
}
