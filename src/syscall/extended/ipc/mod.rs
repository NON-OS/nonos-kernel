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
pub mod msg_ctl;
pub mod msg_ops;
pub mod msg_types;
pub mod sem_ctl;
pub mod sem_ops;
pub mod sem_types;
pub mod shm_ctl;
pub mod shm_ops;
pub mod shm_types;
pub mod stats;

pub use constants::*;
pub use msg_ctl::handle_msgctl;
pub use msg_ops::{handle_msgrcv, handle_msgsnd};
pub use msg_types::handle_msgget;
pub use sem_ctl::handle_semctl;
pub use sem_ops::{handle_semop, handle_semtimedop};
pub use sem_types::handle_semget;
pub use shm_ctl::handle_shmctl;
pub use shm_ops::{handle_shmat, handle_shmdt};
pub use shm_types::handle_shmget;
pub use stats::{get_ipc_stats, IpcStats};
