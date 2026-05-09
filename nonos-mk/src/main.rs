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

//! `marketplace-index` is the host bridge between the operator
//! dashboard and the OS-side decoder. It reads JSON sources, maps
//! them to `nonos_marketplace_abi` types, runs the canonical binary
//! encoder, and Ed25519-signs the exact `signed_bytes` range that
//! the on-OS verifier reads. There is no NOX0 wrapper, no JSON
//! payload on the wire, and no fixed trailer — the live wire form
//! starts with `01 00 00 00` (u32 schema_version = 1 little-endian).
//!
//! The tool refuses to print or persist private key material, and
//! refuses to emit a blob whose serial is not strictly greater than
//! a supplied `--previous-serial`, or whose computed pubkey does
//! not match a supplied `--pubkey` crosscheck.

mod args;
mod commands;
mod encoder;
mod error;
mod json;
mod keys;

use commands::dispatch;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Err(e) = dispatch(&args) {
        let code = e.exit_code();
        eprintln!("marketplace-index: {e}");
        std::process::exit(code);
    }
}
