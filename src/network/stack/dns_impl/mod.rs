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

mod builder;
mod parser;
mod query;

pub(super) use builder::{build_dns_query, build_dns_query_type};
pub(super) use parser::{
    parse_dns_response_a, parse_dns_response_aaaa, parse_dns_response_any,
    parse_dns_response_cname, parse_dns_response_mx, parse_dns_response_ns,
    parse_dns_response_txt,
};
