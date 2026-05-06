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

//! `inspect` re-projects a signed blob back to its JSON form for
//! human review. It does not verify the signature — that is what
//! `verify` is for; `inspect` runs even on blobs whose pubkey the
//! caller does not yet trust, so a reviewer can see what is being
//! asked for before deciding to trust the operator.

use std::path::Path;

use crate::args::Flags;
use crate::error::CliError;
use crate::json::from_index;

use super::read_blob::read_decoded;

pub fn run(flags: &Flags) -> Result<(), CliError> {
    let in_path = flags.require("in").map_err(CliError::Json)?;
    let index = read_decoded(Path::new(in_path))?;
    let pretty = serde_json::to_string_pretty(&from_index(&index))
        .map_err(|e| CliError::Json(e.to_string()))?;
    println!("{pretty}");
    eprintln!(
        "operator_pubkey {} signature_bytes {}",
        hex::encode(index.operator_pubkey),
        index.index_signature.len()
    );
    Ok(())
}
