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

pub mod init;
pub mod drivers;
pub mod vfs_service;
pub mod net_service;
pub mod display_service;
pub mod crypto_service;
pub mod zk_service;
pub mod input_service;
pub mod service_runner;

pub use init::run_init;
pub use drivers::run_driver_manager;
pub use vfs_service::run_vfs_service;
pub use net_service::run_net_service;
pub use display_service::run_display_service;
pub use crypto_service::run_crypto_service;
pub use zk_service::run_zk_service;
pub use input_service::run_input_service;
pub use service_runner::run_service_by_name;
