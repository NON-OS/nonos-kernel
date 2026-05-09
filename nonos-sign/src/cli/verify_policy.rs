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

use nonos_capsule_sign::error::SignError;
use nonos_capsule_sign::verify::decode::decode_trust_anchor_policy;

pub fn run(av: &[String]) -> Result<(), SignError> {
    let path = parse(av)?;
    let bytes = fs::read(&path)?;
    let p = decode_trust_anchor_policy(&bytes)?;
    println!("trust-anchor policy ({} bytes)", bytes.len());
    println!("  epoch              {}", p.epoch);
    println!("  keys               {}", p.keys.len());
    for k in &p.keys {
        println!("    - {} pubkey={}B valid_from_ms={} valid_until_ms={}",
            k.alg.label(), k.pubkey.len(), k.valid_from_ms, k.valid_until_ms);
    }
    println!("  revoked cert serials       {}", p.revoked_cert_serials.len());
    println!("  revoked nonos_ids          {}", p.revoked_nonos_ids.len());
    println!("  revoked publisher_key_ids  {}", p.revoked_publisher_key_ids.len());
    println!("  flags                       0x{:08x}", p.flags);
    Ok(())
}

fn parse(av: &[String]) -> Result<PathBuf, SignError> {
    let mut path: Option<PathBuf> = None;
    let mut i = 0;
    while i < av.len() {
        match av[i].as_str() {
            "--policy" => {
                path = Some(PathBuf::from(av.get(i + 1).ok_or_else(|| usage("--policy <path>"))?));
                i += 2;
            }
            other => return Err(usage(&format!("unknown `{}`", other))),
        }
    }
    path.ok_or_else(|| usage("missing --policy"))
}

fn usage(s: &str) -> SignError {
    SignError::Usage(format!("verify-policy: {}", s))
}
