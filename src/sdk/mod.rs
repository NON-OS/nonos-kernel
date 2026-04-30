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

// Developer-facing SDK surface. App identity, the app registry, runtime
// truth, and manifest types should live under `src/apps` — that migration
// is Wave 5. Until it happens, several of the names this tree exports
// (`registry`, `manifest`, `runtime`, `loader`, `run_app`, `unpack_app`,
// `list_apps`) are still authoritative for shell devtools, the apps
// service, and the in-graphics app browser, so we can't shut them off
// yet.
//
// One thing worth fixing sooner rather than later: `init()` here calls
// `demos::init_demo_apps()`, which loads a demo store index from the
// production boot path. Running demo bootstrap from real boot is exactly
// what we don't want — Wave 5 or 7 owns removing it.
//
// Don't add new authority in this tree. New runtime semantics, new app
// registry state, or new system init behavior belong in `src/apps`.
// What survives long-term here is the developer/client API layer —
// the `ipc_client::*` wrappers and the userland-facing builders.

mod api;
mod api_net;
mod api_net_request;
mod api_storage;
mod api_wallet;
mod app;
mod builder;
mod capsule;
mod demos;
mod events;
pub(crate) mod events_sub;
mod ipc_client;
mod loader;
mod loader_parse;
pub mod manifest;
mod permissions;
pub mod registry;
mod runtime;
mod samples;
mod storage;
mod store;
mod ui;

pub use loader::unpack_app;
pub use registry::list_apps;
pub use runtime::run_app;

pub fn init() {
    demos::init_demo_apps();
}
