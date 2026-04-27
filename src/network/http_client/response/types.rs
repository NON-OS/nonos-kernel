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

use alloc::string::String;
use alloc::vec::Vec;

#[derive(Clone, Debug)]
pub struct HttpResponse {
    pub status_code: u16,
    pub status_text: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub final_url: String,
    pub redirects: u8,
}

impl HttpResponse {
    pub fn new() -> Self {
        Self {
            status_code: 0,
            status_text: String::new(),
            headers: Vec::new(),
            body: Vec::new(),
            final_url: String::new(),
            redirects: 0,
        }
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        let name_lower = name.to_ascii_lowercase();
        for (k, v) in &self.headers {
            if k.to_ascii_lowercase() == name_lower {
                return Some(v.as_str());
            }
        }
        None
    }

    pub fn content_length(&self) -> Option<usize> {
        self.header("content-length").and_then(|v| v.trim().parse().ok())
    }
    pub fn content_type(&self) -> Option<&str> {
        self.header("content-type")
    }
    pub fn location(&self) -> Option<&str> {
        self.header("location")
    }
    pub fn is_redirect(&self) -> bool {
        matches!(self.status_code, 301 | 302 | 303 | 307 | 308)
    }
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status_code)
    }

    pub fn get_set_cookie_headers(&self) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(k, _)| k.to_ascii_lowercase() == "set-cookie")
            .map(|(_, v)| v.as_str())
            .collect()
    }

    pub fn is_keep_alive(&self) -> bool {
        if let Some(conn) = self.header("connection") {
            conn.to_ascii_lowercase().contains("keep-alive")
        } else {
            false
        }
    }

    pub fn body_text(&self) -> Option<String> {
        String::from_utf8(self.body.clone()).ok()
    }
}
