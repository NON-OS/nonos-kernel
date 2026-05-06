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

//! Hand-rolled dev fixture. One unsigned listing with one release
//! that points at a fictional package URL, has zero hashes, and
//! carries an empty `publisher_signature`. The install-readiness
//! evaluator returns `false` for every check on this entry, so the
//! fixture is safe to expose to the IPC surface during local
//! testing without ever launching anything installable.
//!
//! The fixture is built as a fully encoded marketplace-index blob
//! so it goes through the same decode/ingest path as a real
//! operator-published index. Building the blob in code keeps the
//! fixture under git review and avoids a separate binary asset.

extern crate alloc;

use alloc::vec::Vec;

const SCHEMA_VERSION: u32 = 1;
const OPERATOR_ID: &[u8] = b"nonos.marketplace.dev";
const LISTING_ID: &[u8] = b"dev.placeholder";
const APP_NAME: &[u8] = b"Dev Placeholder";
const PUBLISHER_NAME: &[u8] = b"NONOS Dev";
const DESCRIPTION: &[u8] = b"Unsigned dev fixture; install_ready is always false.";
const RELEASE_ID: &[u8] = b"0.0.1";
const PACKAGE_URL: &[u8] = b"";
const ARCH_X86_64: &[u8] = b"x86_64-nonos";

pub fn build() -> Vec<u8> {
    let mut out: Vec<u8> = Vec::new();

    // Header.
    out.extend_from_slice(&SCHEMA_VERSION.to_le_bytes());
    write_lp(&mut out, OPERATOR_ID);
    out.extend_from_slice(&[0u8; 32]); // operator_pubkey: zero, untrusted
    out.extend_from_slice(&0u64.to_le_bytes()); // published_at_ms
    out.extend_from_slice(&0u64.to_le_bytes()); // serial = 0; ingest treats this as the first

    // entries[1]
    out.extend_from_slice(&1u32.to_le_bytes());

    // entry: listing_id, capsule_id, name, publisher_name,
    //        publisher_pubkey, description, price, token, releases
    write_lp(&mut out, LISTING_ID);
    out.extend_from_slice(&[0u8; 32]); // capsule_id zero
    write_lp(&mut out, APP_NAME);
    write_lp(&mut out, PUBLISHER_NAME);
    out.extend_from_slice(&[0u8; 32]); // publisher_pubkey zero
    write_lp(&mut out, DESCRIPTION);

    // price: kind=Free(0), amount=0, period=0
    out.push(0);
    out.extend_from_slice(&0u128.to_le_bytes());
    out.extend_from_slice(&0u64.to_le_bytes());

    // token: symbol "NOX", decimals=18, chain_id=1, contract empty
    write_lp(&mut out, b"NOX");
    out.push(18);
    out.extend_from_slice(&1u64.to_le_bytes());
    write_lp(&mut out, b"");

    // releases[1]
    out.extend_from_slice(&1u32.to_le_bytes());

    // release fields
    write_lp(&mut out, RELEASE_ID);
    out.extend_from_slice(&[0u8; 32]); // manifest_hash zero
    out.extend_from_slice(&[0u8; 32]); // package_hash zero
    write_lp(&mut out, PACKAGE_URL);
    write_lp(&mut out, b""); // publisher_signature empty
    out.extend_from_slice(&1u32.to_le_bytes()); // 1 supported arch
    write_lp(&mut out, ARCH_X86_64);
    out.extend_from_slice(&1u32.to_le_bytes()); // kernel_abi_min
    out.extend_from_slice(&0u32.to_le_bytes()); // 0 required caps

    // validation: status=Pending(1), note empty, validator id empty, ts 0
    out.push(1);
    write_lp(&mut out, b"");
    write_lp(&mut out, b"nonos.marketplace.dev");
    out.extend_from_slice(&0u64.to_le_bytes());

    // index_signature: empty (the dev path skips signature verify)
    write_lp(&mut out, b"");

    out
}

fn write_lp(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}
