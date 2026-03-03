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


mod interceptor;
mod interceptor_types;

pub(crate) use interceptor::{init_interceptor, get_interceptor};
pub(crate) use interceptor_types::InterceptorConfig;

pub(crate) fn init_transparent_routing(config: InterceptorConfig) {
    let _ = init_interceptor(config);
}

pub(crate) fn shutdown_transparent_routing() {
    let guard = get_interceptor().lock();
    if let Some(ref interceptor) = *guard {
        interceptor.stop();
    }
}
