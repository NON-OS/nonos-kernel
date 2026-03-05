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

mod url;
mod response;
mod request;
mod tls_util;
mod client;

pub use url::ParsedUrl;
pub use response::HttpResponse;
pub use request::{HttpMethod, HttpRequestOptions};
pub use client::HttpClient;

use alloc::vec::Vec;

pub fn fetch(url: &str) -> Result<Vec<u8>, &'static str> {
    let client = HttpClient::new();
    let response = client.get(url)?;

    if !response.is_success() {
        return Err("request failed");
    }

    Ok(response.body)
}

pub fn fetch_response(url: &str) -> Result<HttpResponse, &'static str> {
    let client = HttpClient::new();
    client.get(url)
}

pub fn download(url: &str, path: &str) -> Result<usize, &'static str> {
    let data = fetch(url)?;
    let len = data.len();

    crate::fs::nonos_vfs::vfs_write_file(path, &data)
        .map_err(|_| "failed to write file")?;

    Ok(len)
}
