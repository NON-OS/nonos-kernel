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

use nonos_capsule_sign::error::SignError;

use crate::cli::parse::{parse_alg_path, parse_u64, parse_version, require_hybrid_alg_set};

use super::args::Args;
use super::endpoint::parse_endpoint;

pub(super) fn parse(av: &[String]) -> Result<Args, SignError> {
    let mut a = Args {
        cert: PathBuf::new(), namespace: String::new(), version: (0, 0, 0),
        target: String::new(), elf: PathBuf::new(), required_caps: 0,
        optional_caps: 0, endpoints: vec![], pub_seeds: vec![], out: PathBuf::new(),
    };
    let mut have = (false, false, false, false, false, false, false, false);
    let mut i = 0;
    while i < av.len() {
        let n = |k: &str| SignError::Usage(format!("sign-manifest: {}", k));
        let v = |k: &str| av.get(i + 1).ok_or_else(|| n(k));
        match av[i].as_str() {
            "--cert" => { a.cert = PathBuf::from(v("--cert <path>")?); have.0 = true; i += 2; }
            "--namespace" => { a.namespace = v("--namespace <s>")?.clone(); have.1 = true; i += 2; }
            "--version" => { a.version = parse_version(v("--version <m.m.p>")?)?; have.2 = true; i += 2; }
            "--target" => { a.target = v("--target <triple>")?.clone(); have.3 = true; i += 2; }
            "--elf" => { a.elf = PathBuf::from(v("--elf <path>")?); have.4 = true; i += 2; }
            "--required-caps" => { a.required_caps = parse_u64(v("--required-caps <hex>")?)?; have.5 = true; i += 2; }
            "--optional-caps" => { a.optional_caps = parse_u64(v("--optional-caps <hex>")?)?; i += 2; }
            "--endpoint" => { a.endpoints.push(parse_endpoint(v("--endpoint <k:p:n>")?)?); i += 2; }
            "--pub-seed" => { let (g, p) = parse_alg_path(v("--pub-seed <a=p>")?)?; a.pub_seeds.push((g, PathBuf::from(p))); i += 2; }
            "--out" => { a.out = PathBuf::from(v("--out <path>")?); have.6 = true; i += 2; }
            other => return Err(n(&format!("unknown `{}`", other))),
        }
    }
    have.7 = !a.pub_seeds.is_empty();
    if !(have.0 && have.1 && have.2 && have.3 && have.4 && have.5 && have.6 && have.7) {
        return Err(SignError::Usage("sign-manifest: missing required flag (see --help)".into()));
    }
    require_hybrid_alg_set("sign-manifest --pub-seed", &a.pub_seeds)?;
    Ok(a)
}
