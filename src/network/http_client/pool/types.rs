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

extern crate alloc;

use crate::network::onion::tls::TLSConnection;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use spin::Mutex;

pub(super) const MAX_PER_HOST: usize = 6;
pub(super) const MAX_TOTAL: usize = 32;
pub(super) const IDLE_TIMEOUT_MS: u64 = 60_000;
pub(super) const MAX_REQUESTS_PER_CONN: u32 = 100;

pub(crate) struct PooledConnection {
    pub conn_id: u32,
    pub tls: Option<TLSConnection>,
    pub last_used_ms: u64,
    pub request_count: u32,
    pub is_tls: bool,
}

pub(crate) struct ConnectionPool {
    pub(super) entries: Mutex<BTreeMap<String, Vec<PooledConnection>>>,
}

impl ConnectionPool {
    pub(crate) const fn new() -> Self {
        Self { entries: Mutex::new(BTreeMap::new()) }
    }
}
