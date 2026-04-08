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

pub mod app;
pub mod manifest;
pub mod ui;
pub mod api;
mod api_net;
mod api_net_request;
mod api_storage;
mod api_wallet;
pub mod storage;
pub mod registry;
pub mod runtime;
pub mod builder;
mod loader_parse;
pub mod loader;
pub(crate) mod events_sub;
pub mod events;
pub mod permissions;
pub mod samples;
mod demos;
pub mod store;
pub mod ipc_client;
pub mod capsule;

pub use ipc_client::{
    VfsClient, NetClient, CryptoClient, DisplayClient, InputClient, ZkClient,
    AudioClient, GpuClient, AppsClient, AgentsClient, ShellClient,
};

pub use loader::{unpack_app, AppPackage};
pub use registry::list_apps;
pub use runtime::run_app;

pub fn init() { demos::init_demo_apps(); }
