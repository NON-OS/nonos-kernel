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

/// How a page's traffic left the window: straight out, through a manual
/// SOCKS proxy, or over one of the anonymising networks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Route {
    Direct,
    Socks,
    Mixnet,
    Anyone,
}

/// The History page's filter pills, in order.
pub const FILTERS: [&str; 4] = ["All", "Mixnet", "Anyone", "Direct"];

/// Whether a visit over `route` shows under filter pill `i`. A SOCKS proxy
/// carries traffic only on the direct network, so Direct lists it too.
pub fn keeps(i: u8, route: Route) -> bool {
    match i {
        1 => route == Route::Mixnet,
        2 => route == Route::Anyone,
        3 => matches!(route, Route::Direct | Route::Socks),
        _ => true,
    }
}
