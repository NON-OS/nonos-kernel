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

pub mod null;
pub mod zero;
pub mod full;
pub mod random;
pub mod tty;
pub mod ptmx;

pub use null::NullDevice;
pub use zero::ZeroDevice;
pub use full::FullDevice;
pub use random::{RandomDevice, UrandomDevice};
pub use tty::TtyDevice;
pub use ptmx::PtmxDevice;
