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
mod init;
mod destroy;
mod wait;
mod signal;
mod attr;

pub use types::{PthreadCond, PthreadCondattr};
pub use init::pthread_cond_init;
pub use destroy::pthread_cond_destroy;
pub use wait::{pthread_cond_wait, pthread_cond_timedwait};
pub use signal::{pthread_cond_signal, pthread_cond_broadcast};
pub use attr::{pthread_condattr_init, pthread_condattr_setclock};
