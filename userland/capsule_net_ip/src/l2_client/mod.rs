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

mod arp;
mod header;
mod mac;
mod rx;
mod seq;
mod tx;
mod wire;

pub use arp::{resolve as arp_resolve, ArpError};
pub use mac::{read_mac, MacError};
pub use rx::{poll_frame, RxError, MAX_FRAME};
pub use tx::{send_frame, TxError};
