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

mod client_hello;
mod server_hello;
mod parse;
mod finish;
mod wrap;

pub use client_hello::{build_client_hello, build_client_hello_retry};
pub use server_hello::{parse_server_hello, has_tls12_downgrade_sentinel, is_hello_retry_request, ServerHelloResult};
pub use parse::{parse_handshake_view, parse_certificate_chain, parse_certificate_verify};
pub(super) use finish::{build_finished, verify_finished_with_payload, build_cert_verify_context};
pub use wrap::{wrap_handshake, wrap_record};
