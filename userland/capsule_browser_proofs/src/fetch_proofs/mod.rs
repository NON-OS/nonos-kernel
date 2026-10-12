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
#![cfg(test)]

//! Proofs of the fetch machine: its socket calls scripted, its TLS real.

mod closed_tests;
mod connect_fail_tests;
mod connect_tests;
mod cookie_request_tests;
mod conv_tests;
mod deadline_tests;
mod drain_tests;
mod exits_tests;
mod fetch_fixtures;
mod fetch_tls_fixtures;
mod fetch_wire;
mod fetch_wire_calls;
mod hold_tests;
mod load_line_tests;
mod flight_capture_tests;
mod flight_trickle_tests;
mod framing_tests;
mod framing_tls_tests;
mod pace_tests;
mod pool_reuse_tests;
mod pool_reuse_tls_tests;
mod pool_tests;
mod proxy_fault_tests;
mod retain_tests;
mod retry_tests;
mod route_off_tests;
mod sending_tests;
mod stream_tests;
mod stream_room_tests;
mod stream_spare_tests;
mod tls_why_tests;
mod visible_tests;
mod way_tests;
mod words_tests;
