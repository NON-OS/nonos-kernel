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
use alloc::format;

pub(super) const DEFAULT_HTTP_PORT: u16 = 80;
pub(super) const DEFAULT_HTTPS_PORT: u16 = 443;

#[derive(Clone, Debug)]
pub struct ParsedUrl {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path: String,
    pub is_https: bool,
}

impl ParsedUrl {
    pub(super) fn parse(url: &str) -> Result<Self, &'static str> {
        let url = url.trim();

        let (scheme, rest) = if url.starts_with("https://") {
            ("https".into(), &url[8..])
        } else if url.starts_with("http://") {
            ("http".into(), &url[7..])
        } else if url.contains("://") {
            return Err("unsupported scheme");
        } else {
            ("http".into(), url)
        };

        let is_https = scheme == "https";
        let default_port = if is_https { DEFAULT_HTTPS_PORT } else { DEFAULT_HTTP_PORT };

        let (host_port, path) = match rest.find('/') {
            Some(idx) => (&rest[..idx], &rest[idx..]),
            None => (rest, "/"),
        };

        let (host, port): (String, u16) = if let Some(idx) = host_port.rfind(':') {
            let port_str = &host_port[idx + 1..];
            match port_str.parse::<u16>() {
                Ok(p) => (host_port[..idx].into(), p),
                Err(_) => (host_port.into(), default_port),
            }
        } else {
            (host_port.into(), default_port)
        };

        if host.is_empty() {
            return Err("empty host");
        }

        Ok(ParsedUrl {
            scheme,
            host,
            port,
            path: path.into(),
            is_https,
        })
    }

    /// Convert the parsed URL back to a string representation
    pub fn to_string(&self) -> String {
        if (self.is_https && self.port == DEFAULT_HTTPS_PORT) ||
           (!self.is_https && self.port == DEFAULT_HTTP_PORT) {
            format!("{}://{}{}", self.scheme, self.host, self.path)
        } else {
            format!("{}://{}:{}{}", self.scheme, self.host, self.port, self.path)
        }
    }
}

pub(super) fn parse_ipv4(s: &str) -> Option<[u8; 4]> {
    let parts: alloc::vec::Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        return None;
    }

    let mut ip = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        ip[i] = part.parse().ok()?;
    }
    Some(ip)
}

pub(super) fn resolve_host(host: &str) -> Result<[u8; 4], &'static str> {
    if let Some(ip) = parse_ipv4(host) {
        return Ok(ip);
    }

    if host == "localhost" {
        return Ok([127, 0, 0, 1]);
    }

    if let Ok(ips) = crate::network::dns::resolve(host) {
        for ip in ips {
            if let crate::network::ip::IpAddress::V4(v4) = ip {
                return Ok(v4);
            }
        }
    }

    Err("failed to resolve hostname")
}
