// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use crate::crypto::CryptoError;
use crate::crypto::asymmetric::ed25519::{self, KeyPair, Signature};

pub type CryptoResult<T> = core::result::Result<T, CryptoError>;

pub trait Kem {
    type PublicKey;
    type SecretKey;
    type Ciphertext;
    type SharedSecret;

    fn keypair() -> CryptoResult<(Self::PublicKey, Self::SecretKey)>;
    fn encaps(pk: &Self::PublicKey) -> CryptoResult<(Self::Ciphertext, Self::SharedSecret)>;
    fn decaps(ct: &Self::Ciphertext, sk: &Self::SecretKey) -> CryptoResult<Self::SharedSecret>;
}

#[cfg(any(feature = "mlkem512", feature = "mlkem768", feature = "mlkem1024"))]
use crate::crypto::pqc::kyber::{
    KyberPublicKey, KyberSecretKey, KyberCiphertext,
    kyber_keygen, kyber_encaps, kyber_decaps,
};

#[cfg(any(feature = "mlkem512", feature = "mlkem768", feature = "mlkem1024"))]
pub struct KyberKem;

#[cfg(any(feature = "mlkem512", feature = "mlkem768", feature = "mlkem1024"))]
impl Kem for KyberKem {
    type PublicKey = KyberPublicKey;
    type SecretKey = KyberSecretKey;
    type Ciphertext = KyberCiphertext;
    type SharedSecret = [u8; 32];

    fn keypair() -> CryptoResult<(Self::PublicKey, Self::SecretKey)> {
        kyber_keygen().map(|kp| (kp.public_key, kp.secret_key)).map_err(|_| CryptoError::KemError)
    }
    fn encaps(pk: &Self::PublicKey) -> CryptoResult<(Self::Ciphertext, Self::SharedSecret)> {
        kyber_encaps(pk).map_err(|_| CryptoError::KemError)
    }
    fn decaps(ct: &Self::Ciphertext, sk: &Self::SecretKey) -> CryptoResult<Self::SharedSecret> {
        kyber_decaps(ct, sk).map_err(|_| CryptoError::KemError)
    }
}

pub trait Sig {
    type PublicKey;
    type SecretKey;
    type Signature;

    fn keygen() -> CryptoResult<(Self::PublicKey, Self::SecretKey)>;
    fn sign(sk: &Self::SecretKey, msg: &[u8]) -> CryptoResult<Self::Signature>;
    fn verify(pk: &Self::PublicKey, msg: &[u8], sig: &Self::Signature) -> bool;
}

pub struct Ed25519Sig;

impl Sig for Ed25519Sig {
    type PublicKey = [u8; 32];
    type SecretKey = KeyPair;
    type Signature = Signature;

    fn keygen() -> CryptoResult<(Self::PublicKey, Self::SecretKey)> {
        let kp = KeyPair::generate();
        Ok((kp.public, kp))
    }
    fn sign(sk: &Self::SecretKey, msg: &[u8]) -> CryptoResult<Self::Signature> {
        Ok(ed25519::sign(sk, msg))
    }
    fn verify(pk: &Self::PublicKey, msg: &[u8], sig: &Self::Signature) -> bool {
        ed25519::verify(pk, msg, sig)
    }
}

#[cfg(any(feature = "mldsa2", feature = "mldsa3", feature = "mldsa5"))]
use crate::crypto::pqc::dilithium::{
    DilithiumPublicKey, DilithiumSecretKey, DilithiumSignature,
    dilithium_keypair, dilithium_sign, dilithium_verify,
};

#[cfg(any(feature = "mldsa2", feature = "mldsa3", feature = "mldsa5"))]
pub struct DilithiumSig;

#[cfg(any(feature = "mldsa2", feature = "mldsa3", feature = "mldsa5"))]
impl Sig for DilithiumSig {
    type PublicKey = DilithiumPublicKey;
    type SecretKey = DilithiumSecretKey;
    type Signature = DilithiumSignature;

    fn keygen() -> CryptoResult<(Self::PublicKey, Self::SecretKey)> {
        dilithium_keypair().map(|kp| (kp.public_key, kp.secret_key)).map_err(|_| CryptoError::SigError)
    }
    fn sign(sk: &Self::SecretKey, msg: &[u8]) -> CryptoResult<Self::Signature> {
        dilithium_sign(sk, msg).map_err(|_| CryptoError::SigError)
    }
    fn verify(pk: &Self::PublicKey, msg: &[u8], sig: &Self::Signature) -> bool {
        dilithium_verify(pk, msg, sig)
    }
}
