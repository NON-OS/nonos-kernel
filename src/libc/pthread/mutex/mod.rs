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

mod attr;
mod destroy;
mod init;
mod lock;
mod trylock;
mod types;
mod unlock;

pub use attr::{pthread_mutexattr_init, pthread_mutexattr_settype};
pub use destroy::pthread_mutex_destroy;
pub use init::pthread_mutex_init;
pub use lock::pthread_mutex_lock;
pub use trylock::pthread_mutex_trylock;
pub use types::{PthreadMutex, PthreadMutexattr};
pub use types::{PTHREAD_MUTEX_ERRORCHECK, PTHREAD_MUTEX_NORMAL, PTHREAD_MUTEX_RECURSIVE};
pub use unlock::pthread_mutex_unlock;
