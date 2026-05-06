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

//! Boot-time runtime proof for the marketplace capsule. Drives
//! the five rejection paths the userland capsule documents:
//! signed empty index accepted, signed preview index accepted
//! with `install_ready=false`, mutated body rejected, serial
//! rollback rejected, untrusted operator rejected. Gated on
//! `nonos-market-smoketest`.
//!
//! The blobs are produced offline by `nonos-mk-market-fixtures`
//! via the host `marketplace-index` CLI signing against the
//! publicly-known smoketest seed `0x42`-repeated-32. The seed
//! is not secret; the matching pubkey is gated into the
//! userland capsule's bootstrap-trust list by the
//! `smoketest-trust` feature on `nonos_capsule_market`.

use crate::services::lifecycle::smoketest_log;

use super::client;
use super::error::MarketError;
use super::state;

const TAG: &[u8] = b"[MARKET-TEST] ";

const EMPTY_BLOB: &[u8] = include_bytes!("../../../target/test-market/empty.bin");
const PREVIEW_BLOB: &[u8] = include_bytes!("../../../target/test-market/preview.bin");
const MUTATED_BLOB: &[u8] = include_bytes!("../../../target/test-market/mutated.bin");
const UNTRUSTED_BLOB: &[u8] = include_bytes!("../../../target/test-market/untrusted.bin");

const PREVIEW_LISTING_ID: &str = "preview.demo.v1";
const PREVIEW_RELEASE_ID: &str = "preview-0";

pub fn run() {
    if !state::is_alive() {
        return fail_msg(b"capsule not alive");
    }
    mark(b"capsule alive");

    if let Err(e) = client::healthcheck() {
        return fail(b"healthcheck", e);
    }
    mark(b"healthcheck ok");

    if let Err(e) = client::load_index(EMPTY_BLOB) {
        return fail(b"load empty", e);
    }
    match client::list_apps() {
        Ok(0) => mark(b"signed empty accepted"),
        Ok(n) => return fail_msg(error_buf(b"empty: list_apps=", n)),
        Err(e) => return fail(b"list_apps empty", e),
    }

    if let Err(e) = client::load_index(PREVIEW_BLOB) {
        return fail(b"load preview", e);
    }
    match client::list_apps() {
        Ok(n) if n > 0 => mark(b"signed preview accepted"),
        Ok(_) => return fail_msg(b"preview: list_apps must be > 0"),
        Err(e) => return fail(b"list_apps preview", e),
    }
    match client::install_ready(PREVIEW_LISTING_ID, PREVIEW_RELEASE_ID) {
        Ok(v) if !v.install_ready => mark(b"preview install_ready=false"),
        Ok(_) => return fail_msg(b"preview: install_ready must be false"),
        Err(e) => return fail(b"install_ready", e),
    }

    match client::load_index(MUTATED_BLOB) {
        Err(MarketError::SignatureRefused) | Err(MarketError::Malformed) => {
            mark(b"mutated rejected");
        }
        Ok(()) => return fail_msg(b"mutated: must be rejected"),
        Err(e) => return fail(b"mutated", e),
    }

    match client::load_index(EMPTY_BLOB) {
        Err(MarketError::StaleSerial) => mark(b"rollback rejected"),
        Ok(()) => return fail_msg(b"rollback: must be rejected"),
        Err(e) => return fail(b"rollback", e),
    }

    match client::load_index(UNTRUSTED_BLOB) {
        Err(MarketError::SignatureRefused) | Err(MarketError::UntrustedOperator) => {
            mark(b"untrusted rejected");
        }
        Ok(()) => return fail_msg(b"untrusted: must be rejected"),
        Err(e) => return fail(b"untrusted", e),
    }

    mark(b"PASS");
}

fn mark(stage: &[u8]) {
    smoketest_log::mark(TAG, stage);
}

fn fail(stage: &[u8], err: MarketError) {
    smoketest_log::fail_with_err(TAG, stage, err_name(err));
}

fn fail_msg(reason: &[u8]) {
    smoketest_log::fail_msg(TAG, reason);
}

fn error_buf(prefix: &[u8], n: u32) -> &'static [u8] {
    // Reuse a static buffer; only one call site at a time, single-
    // threaded supervisor.
    static mut BUF: [u8; 32] = [0u8; 32];
    unsafe {
        let mut i = 0usize;
        for &b in prefix {
            if i >= BUF.len() {
                break;
            }
            BUF[i] = b;
            i += 1;
        }
        let mut tmp = [0u8; 10];
        let mut len = 0usize;
        let mut v = n;
        if v == 0 {
            tmp[0] = b'0';
            len = 1;
        } else {
            while v > 0 && len < tmp.len() {
                tmp[len] = b'0' + (v % 10) as u8;
                v /= 10;
                len += 1;
            }
        }
        for k in (0..len).rev() {
            if i >= BUF.len() {
                break;
            }
            BUF[i] = tmp[k];
            i += 1;
        }
        &BUF[..i]
    }
}

fn err_name(e: MarketError) -> &'static [u8] {
    match e {
        MarketError::Dead => b"Dead",
        MarketError::Stale => b"Stale",
        MarketError::AccessDenied => b"AccessDenied",
        MarketError::InvalidArgument => b"InvalidArgument",
        MarketError::OversizedRequest => b"OversizedRequest",
        MarketError::NotFound => b"NotFound",
        MarketError::Malformed => b"Malformed",
        MarketError::StaleSerial => b"StaleSerial",
        MarketError::SignatureRefused => b"SignatureRefused",
        MarketError::UntrustedOperator => b"UntrustedOperator",
        MarketError::NoCallerPid => b"NoCallerPid",
        MarketError::TransportFailure => b"TransportFailure",
        MarketError::ProtocolMismatch => b"ProtocolMismatch",
        MarketError::UnexpectedStatus => b"UnexpectedStatus",
    }
}
