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

use super::http_client::HttpClient;
use crate::network::http_client::request::HttpMethod;
use crate::network::http_client::response::HttpResponse;
use crate::network::http_client::url::ParsedUrl;
use alloc::format;
use alloc::string::ToString;

impl HttpClient {
    pub fn get(&self, url: &str) -> Result<HttpResponse, &'static str> {
        self.request(url, HttpMethod::Get, None)
    }
    pub fn head(&self, url: &str) -> Result<HttpResponse, &'static str> {
        self.request(url, HttpMethod::Head, None)
    }
    pub fn post(&self, url: &str, body: &[u8]) -> Result<HttpResponse, &'static str> {
        self.request(url, HttpMethod::Post, Some(body))
    }

    pub fn request(
        &self,
        url: &str,
        method: HttpMethod,
        body: Option<&[u8]>,
    ) -> Result<HttpResponse, &'static str> {
        let mut current_url = url.to_string();
        let mut redirects = 0u8;
        loop {
            let parsed = ParsedUrl::parse(&current_url)?;
            let response = if parsed.is_https {
                self.do_https_request(&parsed, method, body)?
            } else {
                self.do_request(&parsed, method, body)?
            };
            if response.is_redirect() && self.options.follow_redirects {
                if redirects >= self.options.max_redirects {
                    return Err("too many redirects");
                }
                if self.options.use_cookies {
                    let mut jar = crate::network::http_client::cookies::get_cookie_jar().lock();
                    for set_cookie in response.get_set_cookie_headers() {
                        jar.parse_set_cookie(set_cookie, &parsed.host, &parsed.path);
                    }
                }
                if let Some(location) = response.location() {
                    current_url = if location.starts_with("http://")
                        || location.starts_with("https://")
                    {
                        location.to_string()
                    } else if location.starts_with('/') {
                        format!("{}://{}:{}{}", parsed.scheme, parsed.host, parsed.port, location)
                    } else {
                        let base_path = if let Some(idx) = parsed.path.rfind('/') {
                            &parsed.path[..idx + 1]
                        } else {
                            "/"
                        };
                        format!(
                            "{}://{}:{}{}{}",
                            parsed.scheme, parsed.host, parsed.port, base_path, location
                        )
                    };
                    redirects += 1;
                    continue;
                }
            }
            if self.options.use_cookies {
                let mut jar = crate::network::http_client::cookies::get_cookie_jar().lock();
                for set_cookie in response.get_set_cookie_headers() {
                    jar.parse_set_cookie(set_cookie, &parsed.host, &parsed.path);
                }
            }
            let mut final_response = response;
            final_response.final_url = current_url;
            final_response.redirects = redirects;
            return Ok(final_response);
        }
    }
}
