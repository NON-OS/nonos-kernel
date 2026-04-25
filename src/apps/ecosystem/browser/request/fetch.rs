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

use super::helpers::{build_headers, extract_domain, resolve_url, status_text};
use super::proxy::{onion_fetch, proxy_fetch};
use super::types::{FetchError, FetchOptions, FetchResult, HttpMethod};
use crate::apps::ecosystem::browser::state::{get_settings, ProxyMode};
use crate::apps::ecosystem::privacy::{should_block_request, strip_tracking_params};
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

pub fn fetch_page(url: &str, options: FetchOptions) -> Result<FetchResult, FetchError> {
    let settings = get_settings();
    let url = strip_tracking_params(url);

    if settings.https_only && url.starts_with("http://") {
        return Err(FetchError::HttpsRequired);
    }

    let domain = extract_domain(&url).ok_or(FetchError::InvalidUrl)?;

    if settings.tracking_protection && should_block_request(&domain).0 {
        return Err(FetchError::Blocked);
    }

    let mut request_headers = build_headers(&url, &settings);
    for (key, value) in options.headers.iter() {
        request_headers.insert(key.clone(), value.clone());
    }

    let result = match settings.proxy.mode {
        ProxyMode::None => direct_fetch(&url, &options, &request_headers),
        ProxyMode::Onion => onion_fetch(&url, &options, &request_headers),
        ProxyMode::Custom => {
            proxy_fetch(&url, &options, &request_headers, &settings.proxy.host, settings.proxy.port)
        }
        ProxyMode::System => direct_fetch(&url, &options, &request_headers),
    }?;

    if options.follow_redirects && result.is_redirect() {
        if let Some(redirect_url) = result.redirect_url() {
            let resolved_url = resolve_url(&url, redirect_url);
            let mut new_options = options.clone();
            new_options.max_redirects = options.max_redirects.saturating_sub(1);

            if new_options.max_redirects == 0 {
                return Err(FetchError::TooManyRedirects);
            }

            return fetch_page(&resolved_url, new_options);
        }
    }

    Ok(result)
}

fn direct_fetch(
    url: &str,
    options: &FetchOptions,
    headers: &BTreeMap<String, String>,
) -> Result<FetchResult, FetchError> {
    use crate::network::http;

    let header_vec: Vec<(&str, &str)> =
        headers.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();

    let response = match options.method {
        HttpMethod::Get => http::get(url, &header_vec, options.timeout_ms),
        HttpMethod::Post => {
            let body = options.body.as_deref().unwrap_or(&[]);
            http::post(url, body, &header_vec, options.timeout_ms)
        }
        HttpMethod::Put => {
            let body = options.body.as_deref().unwrap_or(&[]);
            http::put(url, body, &header_vec, options.timeout_ms)
        }
        HttpMethod::Delete => http::delete(url, &header_vec, options.timeout_ms),
        HttpMethod::Head => http::head(url, &header_vec, options.timeout_ms),
        _ => http::get(url, &header_vec, options.timeout_ms),
    }
    .map_err(|e| match e {
        http::HttpError::DnsError => FetchError::DnsError,
        http::HttpError::TlsError => FetchError::TlsError,
        http::HttpError::Timeout => FetchError::Timeout,
        http::HttpError::ConnectionRefused => FetchError::ConnectionRefused,
        _ => FetchError::NetworkError,
    })?;

    let mut response_headers = BTreeMap::new();
    for (key, value) in response.headers.iter() {
        response_headers.insert(key.to_lowercase(), value.clone());
    }

    let content_type = response_headers.get("content-type").cloned();
    let content_length = response_headers.get("content-length").and_then(|s| s.parse().ok());

    Ok(FetchResult {
        status_code: response.status_code,
        status_text: status_text(response.status_code),
        headers: response_headers,
        body: response.body,
        final_url: String::from(url),
        content_type,
        content_length,
        title: None,
    })
}
