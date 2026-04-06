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

mod types;
mod constants;
mod state;
mod create;
mod join;
mod exit;
mod detach;
mod self_ops;
mod attr;

pub use types::{PthreadT, StartRoutine, PthreadAttr, ThreadControlBlock};
pub use types::{PTHREAD_CREATE_JOINABLE, PTHREAD_CREATE_DETACHED};
pub use create::pthread_create;
pub use join::pthread_join;
pub use exit::pthread_exit;
pub use detach::pthread_detach;
pub use self_ops::pthread_self;
pub use attr::{pthread_attr_init, pthread_attr_destroy, pthread_attr_setdetachstate, pthread_attr_setstacksize};
