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

use crate::cli::parse::{parse_alg_path, parse_hex32, parse_u64, require_hybrid_alg_set};

use super::args::Args;

pub(super) fn parse(av: &[String]) -> Result<Args, SignError> {
    let mut a = Args {
        serial: 0, nonos_id: [0; 32], ns_globs: vec![], caps_ceiling: 0,
        epoch: 0, valid_from_ms: 0, valid_until_ms: 0, pub_keys: vec![],
        ta_seeds: vec![], metadata: String::new(), out: PathBuf::new(),
    };
    let mut have = (false, false, false, false, false, false, false, false);
    let mut i = 0;
    while i < av.len() {
        let n = |k: &str| SignError::Usage(format!("sign-id-cert: {}", k));
        let v = |k: &str| av.get(i + 1).ok_or_else(|| n(k));
        match av[i].as_str() {
            "--serial" => { a.serial = parse_u64(v("--serial <n>")?)?; have.0 = true; i += 2; }
            "--nonos-id" => { a.nonos_id = parse_hex32(v("--nonos-id <hex32>")?)?; have.1 = true; i += 2; }
            "--ns-glob" => { a.ns_globs.push(v("--ns-glob <s>")?.clone()); i += 2; }
            "--caps-ceiling" => { a.caps_ceiling = parse_u64(v("--caps-ceiling <hex>")?)?; have.2 = true; i += 2; }
            "--epoch" => { a.epoch = parse_u64(v("--epoch <n>")?)?; have.3 = true; i += 2; }
            "--valid-from-ms" => { a.valid_from_ms = parse_u64(v("--valid-from-ms <n>")?)?; have.4 = true; i += 2; }
            "--valid-until-ms" => { a.valid_until_ms = parse_u64(v("--valid-until-ms <n>")?)?; have.5 = true; i += 2; }
            "--pub-key" => { let (g, p) = parse_alg_path(v("--pub-key <a=p>")?)?; a.pub_keys.push((g, PathBuf::from(p))); i += 2; }
            "--ta-seed" => { let (g, p) = parse_alg_path(v("--ta-seed <a=p>")?)?; a.ta_seeds.push((g, PathBuf::from(p))); i += 2; }
            "--metadata" => { a.metadata = v("--metadata <s>")?.clone(); i += 2; }
            "--out" => { a.out = PathBuf::from(v("--out <path>")?); have.6 = true; i += 2; }
            other => return Err(n(&format!("unknown `{}`", other))),
        }
    }
    have.7 = !a.ns_globs.is_empty() && !a.pub_keys.is_empty() && !a.ta_seeds.is_empty();
    if !(have.0 && have.1 && have.2 && have.3 && have.4 && have.5 && have.6 && have.7) {
        return Err(SignError::Usage("sign-id-cert: missing required flag (see --help)".into()));
    }
    require_hybrid_alg_set("sign-id-cert --pub-key", &a.pub_keys)?;
    require_hybrid_alg_set("sign-id-cert --ta-seed", &a.ta_seeds)?;
    Ok(a)
}
