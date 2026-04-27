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

use super::api::{NetworkAccess, SdkApi};
use super::api_net_request::send_request;
use super::app::{AppError, AppResult};
use super::manifest::AppPermission;
use alloc::{
    string::{String, ToString},
    vec::Vec,
};

impl NetworkAccess for SdkApi {
    fn http_get(&self, url: &[u8]) -> AppResult<Vec<u8>> {
        if !self.has_permission(AppPermission::Network) {
            return Err(AppError::PermissionDenied);
        }
        let url_str = core::str::from_utf8(url).map_err(|_| AppError::InvalidInput)?;
        let (host, path) = parse_url(url_str)?;
        let req = build_request(b"GET", host.as_bytes(), path.as_bytes(), &[]);
        send_request(&req, &host)
    }

    fn http_post(&self, url: &[u8], body: &[u8]) -> AppResult<Vec<u8>> {
        if !self.has_permission(AppPermission::Network) {
            return Err(AppError::PermissionDenied);
        }
        let url_str = core::str::from_utf8(url).map_err(|_| AppError::InvalidInput)?;
        let (host, path) = parse_url(url_str)?;
        let req = build_request(b"POST", host.as_bytes(), path.as_bytes(), body);
        send_request(&req, &host)
    }
}

fn parse_url(url: &str) -> AppResult<(String, String)> {
    let url = url.trim_start_matches("http://").trim_start_matches("https://");
    let (host, path): (String, String) = match url.find('/') {
        Some(i) => (url[..i].to_string(), url[i..].to_string()),
        None => (url.to_string(), "/".to_string()),
    };
    if host.is_empty() {
        return Err(AppError::InvalidInput);
    }
    Ok((host, path))
}

fn build_request(method: &[u8], host: &[u8], path: &[u8], body: &[u8]) -> Vec<u8> {
    let mut req = Vec::with_capacity(512 + body.len());
    req.extend_from_slice(method);
    req.extend_from_slice(b" ");
    req.extend_from_slice(path);
    req.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    req.extend_from_slice(host);
    req.extend_from_slice(b"\r\nConnection: close\r\n");
    if !body.is_empty() {
        req.extend_from_slice(b"Content-Length: ");
        req.extend_from_slice(alloc::format!("{}", body.len()).as_bytes());
        req.extend_from_slice(b"\r\n\r\n");
        req.extend_from_slice(body);
    } else {
        req.extend_from_slice(b"\r\n");
    }
    req
}
