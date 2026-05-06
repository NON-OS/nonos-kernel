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

//! Userland-status -> kernel-error mapping. The userland capsule
//! returns Linux-shape errnos in the response status field; this
//! function lifts them into the structured `MarketError`. The
//! status codes here mirror `userland/capsule_market/src/protocol/
//! errno.rs` and the load-index error mapping in
//! `userland/capsule_market/src/server/handlers/load_index.rs`.

use super::super::error::MarketError;

const E_INVAL: i32 = -22;
const E_IO: i32 = -5;
const E_NODATA: i32 = -61;
const E_KEYREJECTED: i32 = -129;
const E_STALE: i32 = -116;
const E_MSGSIZE: i32 = -90;

pub(super) fn lift(status: i32) -> MarketError {
    match status {
        E_INVAL => MarketError::InvalidArgument,
        E_IO => MarketError::Malformed,
        E_NODATA => MarketError::NotFound,
        E_KEYREJECTED => MarketError::SignatureRefused,
        E_STALE => MarketError::StaleSerial,
        E_MSGSIZE => MarketError::OversizedRequest,
        _ => MarketError::UnexpectedStatus,
    }
}
