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

//! `OP_INSTALL_READY`. The userland capsule evaluates a hard AND
//! of nine install gates and returns the verdict as six bytes:
//! one for the AND-result followed by the per-check bits. The
//! kernel surfaces the result as a structured value so a caller
//! can short-circuit on the AND-result while still being able to
//! tell which gate refused.

use alloc::vec::Vec;

use super::super::capability::gate_call;
use super::super::error::MarketError;
use super::super::protocol::{encode_request, OP_INSTALL_READY};
use super::seq::next_request_id;
use super::status_map::lift;
use super::transport::round_trip;

const READINESS_LEN: usize = 6;

#[derive(Debug, Clone, Copy)]
pub struct InstallReadiness {
    pub install_ready: bool,
    pub index_signature_valid: bool,
    pub package_url_present: bool,
    pub publisher_signature_present: bool,
    pub validation_passed: bool,
    pub arch_match: bool,
}

pub fn install_ready(
    listing_id: &str,
    release_id: &str,
) -> Result<InstallReadiness, MarketError> {
    let _caller = gate_call()?;
    let mut body: Vec<u8> = Vec::with_capacity(8 + listing_id.len() + release_id.len());
    body.extend_from_slice(&(listing_id.len() as u32).to_le_bytes());
    body.extend_from_slice(listing_id.as_bytes());
    body.extend_from_slice(&(release_id.len() as u32).to_le_bytes());
    body.extend_from_slice(release_id.as_bytes());

    let request_id = next_request_id();
    let frame = encode_request(OP_INSTALL_READY, 0, request_id, &body);
    let resp = round_trip(request_id, frame)?;
    if resp.status != 0 {
        return Err(lift(resp.status));
    }
    if resp.body.len() < READINESS_LEN {
        return Err(MarketError::ProtocolMismatch);
    }
    Ok(InstallReadiness {
        install_ready: resp.body[0] != 0,
        index_signature_valid: resp.body[1] != 0,
        package_url_present: resp.body[2] != 0,
        publisher_signature_present: resp.body[3] != 0,
        validation_passed: resp.body[4] != 0,
        arch_match: resp.body[5] != 0,
    })
}
