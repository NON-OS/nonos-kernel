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

pub mod check;
pub mod types;

pub use check::{check_service_cap, has_capability, verify_caller_cap, CapError};
pub use types::{
    ServiceCap, CAP_ADMIN, CAP_AGENTS, CAP_APPS, CAP_AUDIO, CAP_CRYPTO, CAP_DISPLAY, CAP_DRIVER,
    CAP_ENTROPY, CAP_GPU, CAP_INPUT, CAP_KERNEL, CAP_KEYRING, CAP_MEMORY, CAP_NET, CAP_PROCESS,
    CAP_SHELL, CAP_STORAGE, CAP_TLS, CAP_UDEV, CAP_VFS, CAP_WALLET, CAP_ZK,
};
