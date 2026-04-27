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

mod agents;
mod apps;
mod audio;
mod crypto;
mod display;
mod gpu;
mod input;
mod network;
mod shell;
mod vfs;
mod zk;

pub use agents::AgentsClient;
pub use apps::AppsClient;
pub use audio::AudioClient;
pub use crypto::CryptoClient;
pub use display::DisplayClient;
pub use gpu::GpuClient;
pub use input::InputClient;
pub use network::NetClient;
pub use shell::ShellClient;
pub use vfs::VfsClient;
pub use zk::ZkClient;
