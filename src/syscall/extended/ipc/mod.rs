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

pub mod constants;
pub mod msg;
pub mod sem;
pub mod shm;
pub mod stats;

pub use constants::*;
pub use shm::{handle_shmget, handle_shmat, handle_shmdt, handle_shmctl};
pub use sem::{handle_semget, handle_semop, handle_semtimedop, handle_semctl};
pub use msg::{handle_msgget, handle_msgsnd, handle_msgrcv, handle_msgctl};
pub use stats::{IpcStats, get_ipc_stats};
