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

//! RFC 2131 client state machine. The transitions match figure 5
//! in the RFC; renewal (RENEWING / REBINDING) is owned by the
//! caller via the lease-timer driver in `main.rs`.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Init,
    Selecting,
    Requesting,
    Bound,
    Renewing,
    Rebinding,
    InitReboot,
}

impl State {
    pub fn next_on_offer(self) -> Option<Self> {
        match self {
            Self::Selecting => Some(Self::Requesting),
            _ => None,
        }
    }

    pub fn next_on_ack(self) -> Option<Self> {
        match self {
            Self::Requesting | Self::Renewing | Self::Rebinding | Self::InitReboot => {
                Some(Self::Bound)
            }
            _ => None,
        }
    }

    pub fn next_on_nak(self) -> Self {
        Self::Init
    }
}
