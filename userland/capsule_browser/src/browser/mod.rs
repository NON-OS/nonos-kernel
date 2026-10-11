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

/* The render engine (parse -> style -> box layout) is the part the host render
 * harness compiles standalone; everything that touches the syscall runtime,
 * the network, the compositor or the JS engine is gated out under `harness`. */
pub mod css;
pub mod dom;
pub mod fonts;
pub mod html;
pub mod http;
pub mod layout;
pub mod manifest;
pub mod ui;
pub mod url;

#[cfg(not(feature = "harness"))]
mod app;
#[cfg(not(feature = "harness"))]
pub mod cookie;
#[cfg(not(feature = "harness"))]
pub(crate) mod event;
#[cfg(not(feature = "harness"))]
pub mod fetch;
pub mod image;
#[cfg(not(feature = "harness"))]
mod js;
#[cfg(not(feature = "harness"))]
mod net;

/// The network the browser starts on: the system's default, which setup asks
/// for and Settings changes.
pub fn start_on_system_network() {
    net::mixnet::from_system_default();
}
#[cfg(not(feature = "harness"))]
mod omnibox;
#[cfg(not(feature = "harness"))]
mod paint;
#[cfg(not(feature = "harness"))]
mod proxy;
#[cfg(not(feature = "harness"))]
pub mod qjs_run;
#[cfg(not(feature = "harness"))]
mod reader;
pub mod short_name;
#[cfg(not(feature = "harness"))]
mod settings;
#[cfg(not(feature = "harness"))]
mod shell;
#[cfg(not(feature = "harness"))]
pub mod state;
#[cfg(not(feature = "harness"))]
mod tab_close;
#[cfg(not(feature = "harness"))]
mod tab_focus;
#[cfg(not(feature = "harness"))]
mod tab_groups;
#[cfg(not(feature = "harness"))]
mod tab_scope;
#[cfg(not(feature = "harness"))]
mod tab_switch;
#[cfg(not(feature = "harness"))]
mod tabs;
#[cfg(not(feature = "harness"))]
/* TLS lives in the nonos_tls crate now, shared rather than copied. The
 * alias keeps every call site here reading the same as before. */
pub use nonos_tls as tls13;

#[cfg(not(feature = "harness"))]
pub use app::Browser;
