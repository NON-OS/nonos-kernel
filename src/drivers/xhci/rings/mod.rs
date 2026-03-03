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

mod command;
mod endpoint;
mod event;
mod transfer;

pub use command::CommandRing;
pub use endpoint::EndpointRing;
pub use event::EventRing;
pub use transfer::TransferRing;

#[cfg(test)]
mod tests {
    use super::super::constants::*;

    #[test]
    fn test_ring_constants() {
        assert!(MIN_RING_SIZE >= 16);
        assert!(MAX_RING_SIZE >= MIN_RING_SIZE);
    }
}
