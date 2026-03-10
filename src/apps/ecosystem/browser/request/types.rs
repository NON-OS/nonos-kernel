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
use alloc::vec::Vec;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchError {
    NetworkError,
    DnsError,
    TlsError,
    Timeout,
    InvalidUrl,
    Blocked,
    TooManyRedirects,
    ConnectionRefused,
    InvalidResponse,
    HttpsRequired,
}

#[derive(Debug, Clone)]
pub struct FetchOptions {
    pub method: HttpMethod,
    pub headers: BTreeMap<String, String>,
    pub body: Option<Vec<u8>>,
    pub timeout_ms: u32,
    pub follow_redirects: bool,
    pub max_redirects: u8,
    pub verify_ssl: bool,
}

impl Default for FetchOptions {
    fn default() -> Self {
        Self {
            method: HttpMethod::Get,
            headers: BTreeMap::new(),
            body: None,
            timeout_ms: 30000,
            follow_redirects: true,
            max_redirects: 10,
            verify_ssl: true,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    Get,
    Post,
    Put,
    Delete,
    Head,
    Options,
    Patch,
}

impl HttpMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            HttpMethod::Get => "GET",
            HttpMethod::Post => "POST",
            HttpMethod::Put => "PUT",
            HttpMethod::Delete => "DELETE",
            HttpMethod::Head => "HEAD",
            HttpMethod::Options => "OPTIONS",
            HttpMethod::Patch => "PATCH",
        }
    }
}

#[derive(Debug, Clone)]
pub struct FetchResult {
    pub status_code: u16,
    pub status_text: String,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
    pub final_url: String,
    pub content_type: Option<String>,
    pub content_length: Option<usize>,
    pub title: Option<String>,
}

impl FetchResult {
    pub fn is_success(&self) -> bool {
        self.status_code >= 200 && self.status_code < 300
    }

    pub fn is_redirect(&self) -> bool {
        self.status_code >= 300 && self.status_code < 400
    }

    pub fn is_client_error(&self) -> bool {
        self.status_code >= 400 && self.status_code < 500
    }

    pub fn is_server_error(&self) -> bool {
        self.status_code >= 500
    }

    pub fn body_as_string(&self) -> Option<String> {
        String::from_utf8(self.body.clone()).ok()
    }

    pub fn redirect_url(&self) -> Option<&String> {
        self.headers.get("location")
    }
}
