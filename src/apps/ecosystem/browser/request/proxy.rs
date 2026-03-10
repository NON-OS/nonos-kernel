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

use alloc::collections::BTreeMap;
use alloc::string::String;
use super::types::{FetchError, FetchOptions, FetchResult};
use super::helpers::{build_http_request, parse_http_response, parse_url};

pub(super) fn onion_fetch(
    url: &str,
    options: &FetchOptions,
    headers: &BTreeMap<String, String>,
) -> Result<FetchResult, FetchError> {
    use crate::network::socks;

    let proxy_conn = socks::connect("127.0.0.1", 9050, options.timeout_ms)
        .map_err(|_| FetchError::NetworkError)?;

    let (host, port, path) = parse_url(url).ok_or(FetchError::InvalidUrl)?;

    socks::connect_target(&proxy_conn, &host, port, options.timeout_ms)
        .map_err(|_| FetchError::NetworkError)?;

    let request = build_http_request(options.method.as_str(), &host, &path, headers, options.body.as_deref());
    socks::send(&proxy_conn, &request).map_err(|_| FetchError::NetworkError)?;

    let response_data = socks::recv(&proxy_conn, options.timeout_ms)
        .map_err(|_| FetchError::NetworkError)?;

    parse_http_response(&response_data, url)
}

pub(super) fn proxy_fetch(
    url: &str,
    options: &FetchOptions,
    headers: &BTreeMap<String, String>,
    proxy_host: &str,
    proxy_port: u16,
) -> Result<FetchResult, FetchError> {
    use crate::network::socks;

    let proxy_conn = socks::connect(proxy_host, proxy_port, options.timeout_ms)
        .map_err(|_| FetchError::NetworkError)?;

    let (host, port, path) = parse_url(url).ok_or(FetchError::InvalidUrl)?;

    socks::connect_target(&proxy_conn, &host, port, options.timeout_ms)
        .map_err(|_| FetchError::NetworkError)?;

    let request = build_http_request(options.method.as_str(), &host, &path, headers, options.body.as_deref());
    socks::send(&proxy_conn, &request).map_err(|_| FetchError::NetworkError)?;

    let response_data = socks::recv(&proxy_conn, options.timeout_ms)
        .map_err(|_| FetchError::NetworkError)?;

    parse_http_response(&response_data, url)
}
