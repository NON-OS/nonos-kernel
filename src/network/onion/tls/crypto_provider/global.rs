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

use super::kernel::KERNEL_TLS_CRYPTO;
use super::traits::TlsCrypto;
use spin::Once;

static TLS_CRYPTO: Once<&'static dyn TlsCrypto> = Once::new();

pub fn init_tls_crypto(provider: &'static dyn TlsCrypto) {
    TLS_CRYPTO.call_once(|| provider);
}

#[inline]
pub(in crate::network::onion::tls) fn crypto() -> &'static dyn TlsCrypto {
    *TLS_CRYPTO.call_once(|| &KERNEL_TLS_CRYPTO as &'static dyn TlsCrypto)
}

pub fn is_tls_crypto_initialized() -> bool {
    TLS_CRYPTO.get().is_some()
}
