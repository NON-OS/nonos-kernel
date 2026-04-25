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

use super::super::constants::MAX_DESC_CHAIN_LEN;
use super::super::error::VirtioNetError;

pub fn validate_descriptor_index(idx: u16, queue_size: u16) -> Result<(), VirtioNetError> {
    if idx >= queue_size {
        return Err(VirtioNetError::DescriptorOutOfBounds);
    }
    Ok(())
}

pub fn validate_chain_length(chain: &[u16]) -> Result<(), VirtioNetError> {
    if chain.is_empty() {
        return Err(VirtioNetError::QueueError);
    }
    if chain.len() > MAX_DESC_CHAIN_LEN {
        return Err(VirtioNetError::DescriptorChainTooLong);
    }
    Ok(())
}
