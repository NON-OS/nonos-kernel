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

pub mod api;
mod api_net;
mod api_net_request;
mod api_storage;
mod api_wallet;
pub mod app;
pub mod builder;
pub mod capsule;
mod demos;
pub mod events;
pub(crate) mod events_sub;
pub mod ipc_client;
pub mod loader;
mod loader_parse;
pub mod manifest;
pub mod permissions;
pub mod registry;
pub mod runtime;
pub mod samples;
pub mod storage;
pub mod store;
pub mod ui;

pub use ipc_client::{
    AgentsClient, AppsClient, AudioClient, CryptoClient, DisplayClient, GpuClient, InputClient,
    NetClient, ShellClient, VfsClient, ZkClient,
};

pub use loader::{unpack_app, AppPackage};
pub use registry::list_apps;
pub use runtime::run_app;

pub fn init() {
    demos::init_demo_apps();
}
