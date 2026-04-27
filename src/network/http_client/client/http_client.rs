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

use crate::network::http_client::pool::ConnectionPool;
use crate::network::http_client::request::HttpRequestOptions;
use crate::network::onion::tls::SessionCache;

pub(in crate::network::http_client) static HTTPS_SESSION_CACHE: SessionCache = SessionCache::new();
pub(in crate::network::http_client) static CONNECTION_POOL: ConnectionPool = ConnectionPool::new();

pub struct HttpClient {
    pub(super) options: HttpRequestOptions,
}

impl HttpClient {
    pub fn new() -> Self {
        Self { options: HttpRequestOptions::default() }
    }
    pub fn with_options(options: HttpRequestOptions) -> Self {
        Self { options }
    }
}
