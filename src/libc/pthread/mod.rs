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

pub mod cond;
pub mod mutex;
pub mod thread;
pub mod tls;

pub use cond::{
    pthread_cond_broadcast, pthread_cond_destroy, pthread_cond_init, pthread_cond_signal,
    pthread_cond_timedwait, pthread_cond_wait,
};
pub use mutex::{
    pthread_mutex_destroy, pthread_mutex_init, pthread_mutex_lock, pthread_mutex_trylock,
    pthread_mutex_unlock,
};
pub use thread::{
    pthread_attr_destroy, pthread_attr_init, pthread_attr_setdetachstate, pthread_attr_setstacksize,
};
pub use thread::{pthread_create, pthread_detach, pthread_exit, pthread_join, pthread_self};
pub use thread::{PthreadAttr, PthreadT};
pub use tls::{pthread_getspecific, pthread_key_create, pthread_key_delete, pthread_setspecific};
