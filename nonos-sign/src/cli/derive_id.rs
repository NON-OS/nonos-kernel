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
use nonos_capsule_sign::wire::derive::derive_nonos_id;

pub fn run(args: &[String]) -> Result<(), SignError> {
    let (handle, domain, recovery) = parse_args(args)?;
    let id = derive_nonos_id(handle.as_bytes(), domain.as_bytes(), recovery.as_bytes())?;
    println!("{}", hex_lower(&id));
    Ok(())
}

fn parse_args(args: &[String]) -> Result<(String, String, String), SignError> {
    let mut handle: Option<String> = None;
    let mut domain: Option<String> = None;
    let mut recovery: String = String::new();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--handle" => {
                handle = Some(args.get(i + 1).ok_or_else(|| usage("--handle <s>"))?.clone());
                i += 2;
            }
            "--domain" => {
                domain = Some(args.get(i + 1).ok_or_else(|| usage("--domain <s>"))?.clone());
                i += 2;
            }
            "--recovery" => {
                recovery = args.get(i + 1).ok_or_else(|| usage("--recovery <s>"))?.clone();
                i += 2;
            }
            other => return Err(usage(&format!("unknown arg `{}`", other))),
        }
    }
    Ok((
        handle.ok_or_else(|| usage("missing --handle"))?,
        domain.ok_or_else(|| usage("missing --domain"))?,
        recovery,
    ))
}

fn usage(s: &str) -> SignError {
    SignError::Usage(format!("derive-id: {}", s))
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}
