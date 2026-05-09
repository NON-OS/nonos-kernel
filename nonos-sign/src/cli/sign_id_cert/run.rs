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

use nonos_capsule_sign::error::SignError;
use nonos_capsule_sign::wire::derive::derive_nonos_id_cert_id;
use nonos_capsule_sign::wire::nonos_id_cert::{assemble, encode_signed_region};

use super::{build, parse::parse, sign::ta_signatures};

pub fn run(av: &[String]) -> Result<(), SignError> {
    let a = parse(av)?;
    let inputs = build::inputs(&a)?;
    let body = encode_signed_region(&inputs)?;
    let sigs = ta_signatures(&body, &a.ta_seeds)?;
    let bytes = assemble(&body, &sigs)?;
    fs::write(&a.out, &bytes)?;
    let cert_id = derive_nonos_id_cert_id(&bytes);
    println!(
        "wrote nonos_id_cert {} ({} bytes, cert_id {})",
        a.out.display(),
        bytes.len(),
        hex_lower(&cert_id)
    );
    Ok(())
}

fn hex_lower(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}
