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

//! Transparent Onion Routing
//!
//! This module intercepts all outbound TCP/IP traffic and routes it through
//! the onion network automatically, providing network-level anonymity without
//! requiring applications to be aware of the routing.

mod interceptor;

pub(crate) use interceptor::{InterceptorConfig, init_interceptor, get_interceptor};

pub(crate) fn init_transparent_routing(config: InterceptorConfig) {
    let _ = init_interceptor(config);
}

pub(crate) fn shutdown_transparent_routing() {
    let guard = get_interceptor().lock();
    if let Some(ref interceptor) = *guard {
        interceptor.stop();
    }
}
