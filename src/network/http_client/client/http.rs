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
use crate::network::http_client::request::{build_request, HttpMethod};
use crate::network::http_client::response::{parse_response, HttpResponse};
use crate::network::http_client::url::{resolve_host, ParsedUrl};

impl HttpClient {
    pub(super) fn do_request(
        &self,
        url: &ParsedUrl,
        method: HttpMethod,
        body: Option<&[u8]>,
    ) -> Result<HttpResponse, &'static str> {
        let ip = resolve_host(&url.host)?;
        let request = build_request(url, method, body, &self.options);
        let stack =
            crate::network::stack::get_network_stack().ok_or("network stack not initialized")?;
        let raw_response =
            stack.http_request(ip, url.port, &request, self.options.timeout_ms as u32)?;
        parse_response(&raw_response)
    }
}
