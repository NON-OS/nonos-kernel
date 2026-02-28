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

#[cfg(test)]
pub(super) unsafe fn keypair(_pk: *mut u8, _sk: *mut u8) -> i32 { -1 }
#[cfg(test)]
pub(super) unsafe fn sign(_sig: *mut u8, _siglen: *mut usize, _m: *const u8, _mlen: usize, _sk: *const u8) -> i32 { -1 }
#[cfg(test)]
pub(super) unsafe fn verify(_sig: *const u8, _siglen: usize, _m: *const u8, _mlen: usize, _pk: *const u8) -> i32 { -1 }

#[cfg(all(not(test), feature = "mldsa2", not(feature = "mldsa3"), not(feature = "mldsa5")))]
extern "C" {
    fn PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_keypair(pk: *mut u8, sk: *mut u8) -> i32;
    fn PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> i32;
    fn PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> i32;
}

#[cfg(all(not(test), feature = "mldsa2", not(feature = "mldsa3"), not(feature = "mldsa5")))]
pub(super) unsafe fn keypair(pk: *mut u8, sk: *mut u8) -> i32 {
    unsafe { PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_keypair(pk, sk) }
}
#[cfg(all(not(test), feature = "mldsa2", not(feature = "mldsa3"), not(feature = "mldsa5")))]
pub(super) unsafe fn sign(sig: *mut u8, siglen: *mut usize, m: *const u8, mlen: usize, sk: *const u8) -> i32 {
    unsafe { PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk) }
}
#[cfg(all(not(test), feature = "mldsa2", not(feature = "mldsa3"), not(feature = "mldsa5")))]
pub(super) unsafe fn verify(sig: *const u8, siglen: usize, m: *const u8, mlen: usize, pk: *const u8) -> i32 {
    unsafe { PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk) }
}

#[cfg(all(not(test), feature = "mldsa3", not(feature = "mldsa2"), not(feature = "mldsa5")))]
extern "C" {
    fn PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_keypair(pk: *mut u8, sk: *mut u8) -> i32;
    fn PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> i32;
    fn PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> i32;
}

#[cfg(all(not(test), feature = "mldsa3", not(feature = "mldsa2"), not(feature = "mldsa5")))]
pub(super) unsafe fn keypair(pk: *mut u8, sk: *mut u8) -> i32 {
    unsafe { PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_keypair(pk, sk) }
}
#[cfg(all(not(test), feature = "mldsa3", not(feature = "mldsa2"), not(feature = "mldsa5")))]
pub(super) unsafe fn sign(sig: *mut u8, siglen: *mut usize, m: *const u8, mlen: usize, sk: *const u8) -> i32 {
    unsafe { PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk) }
}
#[cfg(all(not(test), feature = "mldsa3", not(feature = "mldsa2"), not(feature = "mldsa5")))]
pub(super) unsafe fn verify(sig: *const u8, siglen: usize, m: *const u8, mlen: usize, pk: *const u8) -> i32 {
    unsafe { PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk) }
}

#[cfg(all(not(test), feature = "mldsa5", not(feature = "mldsa2"), not(feature = "mldsa3")))]
extern "C" {
    fn PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_keypair(pk: *mut u8, sk: *mut u8) -> i32;
    fn PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_signature(
        sig: *mut u8,
        siglen: *mut usize,
        m: *const u8,
        mlen: usize,
        sk: *const u8,
    ) -> i32;
    fn PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_verify(
        sig: *const u8,
        siglen: usize,
        m: *const u8,
        mlen: usize,
        pk: *const u8,
    ) -> i32;
}

#[cfg(all(not(test), feature = "mldsa5", not(feature = "mldsa2"), not(feature = "mldsa3")))]
pub(super) unsafe fn keypair(pk: *mut u8, sk: *mut u8) -> i32 {
    unsafe { PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_keypair(pk, sk) }
}
#[cfg(all(not(test), feature = "mldsa5", not(feature = "mldsa2"), not(feature = "mldsa3")))]
pub(super) unsafe fn sign(sig: *mut u8, siglen: *mut usize, m: *const u8, mlen: usize, sk: *const u8) -> i32 {
    unsafe { PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_signature(sig, siglen, m, mlen, sk) }
}
#[cfg(all(not(test), feature = "mldsa5", not(feature = "mldsa2"), not(feature = "mldsa3")))]
pub(super) unsafe fn verify(sig: *const u8, siglen: usize, m: *const u8, mlen: usize, pk: *const u8) -> i32 {
    unsafe { PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_verify(sig, siglen, m, mlen, pk) }
}
