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

pub fn generate_wallet_entropy(buffer: &mut [u8]) {
    #[cfg(feature = "std")]
    {
        crate::crypto::util::rng::fill_random_bytes(buffer);
        return;
    }

    #[cfg(not(feature = "std"))]
    generate_kernel_wallet_entropy(buffer);
}

#[cfg(not(feature = "std"))]
fn generate_kernel_wallet_entropy(buffer: &mut [u8]) {
    let mut pool = super::pool::EntropyPool::new();
    let timing = super::timing::collect(&mut pool);

    super::system::collect(&mut pool, timing);
    super::csprng::collect(&mut pool);
    super::super::hardware_mix::mix_hardware_entropy(pool.bytes_mut());
    super::finalize::fill_output(buffer, pool.bytes());
    pool.zeroize();
}
