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

use nonos_capsule_sign::error::SignError;

use super::{
    derive_id, keygen, sign_id_cert, sign_manifest, trust_policy, usage, verify_cert,
    verify_manifest, verify_policy,
};

pub fn dispatch(argv: &[String]) -> Result<(), SignError> {
    if argv.len() < 2 {
        return Err(SignError::Usage(usage::TOP.into()));
    }
    let rest = &argv[2..];
    match argv[1].as_str() {
        "keygen" => keygen::run(rest),
        "derive-id" => derive_id::run(rest),
        "mk-trust-policy" => trust_policy::run(rest),
        "sign-id-cert" => sign_id_cert::run(rest),
        "sign-manifest" => sign_manifest::run(rest),
        "verify-policy" => verify_policy::run(rest),
        "verify-cert" => verify_cert::run(rest),
        "verify-manifest" => verify_manifest::run(rest),
        "help" | "-h" | "--help" => {
            println!("{}", usage::TOP);
            Ok(())
        }
        other => Err(SignError::Usage(format!("unknown subcommand `{}`\n\n{}", other, usage::TOP))),
    }
}
