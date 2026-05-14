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

//! RFC 793 connection states. Stored in the per-connection control
//! block and inspected by the segment receive path to decide how
//! to handle SYN / ACK / FIN / RST inputs.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Closed,
    Listen,
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
}

impl State {
    pub fn is_synchronised(self) -> bool {
        !matches!(self, Self::Closed | Self::Listen | Self::SynSent | Self::SynReceived)
    }

    pub fn accepts_data(self) -> bool {
        matches!(self, Self::Established | Self::FinWait1 | Self::FinWait2)
    }
}
