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

use nonos_capsule_sign::algs::ed25519::Ed25519;
use nonos_capsule_sign::algs::mldsa65::MlDsa65;
use nonos_capsule_sign::algs::traits::{KeyPair, Signer};
use nonos_capsule_sign::algs::{parse_alg, AlgId};
use nonos_capsule_sign::error::SignError;
use nonos_capsule_sign::keys::write_keypair;

pub fn run(args: &[String]) -> Result<(), SignError> {
    let (alg, out) = parse_args(args)?;
    let kp: KeyPair = match alg {
        AlgId::Ed25519 => Ed25519::keygen_random()?,
        AlgId::MlDsa65 => MlDsa65::keygen_random()?,
        other => return Err(SignError::UnsupportedAlg(other.label().to_string())),
    };
    write_keypair(&out, alg, &kp.seed, &kp.pubkey)?;
    println!(
        "wrote {}.seed (chmod 600) and {}.pub for {}",
        out.display(),
        out.display(),
        alg.label()
    );
    Ok(())
}

fn parse_args(args: &[String]) -> Result<(AlgId, PathBuf), SignError> {
    let mut alg: Option<AlgId> = None;
    let mut out: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--alg" => {
                alg = Some(parse_alg(args.get(i + 1).ok_or_else(|| usage("--alg <name>"))?)?);
                i += 2;
            }
            "--out" => {
                out = Some(PathBuf::from(args.get(i + 1).ok_or_else(|| usage("--out <prefix>"))?));
                i += 2;
            }
            other => return Err(usage(&format!("unknown arg `{}`", other))),
        }
    }
    Ok((alg.ok_or_else(|| usage("missing --alg"))?, out.ok_or_else(|| usage("missing --out"))?))
}

fn usage(s: &str) -> SignError {
    SignError::Usage(format!("keygen: {}", s))
}
