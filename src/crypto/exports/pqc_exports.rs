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

#[cfg(any(feature = "mldsa2", feature = "mldsa3", feature = "mldsa5"))]
pub use super::super::pqc::dilithium;
#[cfg(any(feature = "mlkem512", feature = "mlkem768", feature = "mlkem1024"))]
pub use super::super::pqc::kyber;
pub use super::super::pqc::mceliece;
pub use super::super::pqc::ntru;
pub use super::super::pqc::quantum;
pub use super::super::pqc::sphincs;

#[cfg(any(feature = "mlkem512", feature = "mlkem768", feature = "mlkem1024"))]
pub use super::super::pqc::kyber::{
    kyber_decaps, kyber_deserialize_ciphertext, kyber_deserialize_public_key,
    kyber_deserialize_secret_key, kyber_encaps, kyber_keygen, kyber_serialize_ciphertext,
    kyber_serialize_public_key, kyber_serialize_secret_key, KyberCiphertext, KyberKeyPair,
    KyberPublicKey, KyberSecretKey, CIPHERTEXT_BYTES as KYBER_CT_BYTES, KYBER_PARAM_NAME,
    PUBLICKEY_BYTES as KYBER_PUB_BYTES, SECRETKEY_BYTES as KYBER_SK_BYTES,
};

#[cfg(any(feature = "mldsa2", feature = "mldsa3", feature = "mldsa5"))]
pub use super::super::pqc::dilithium::{
    dilithium_deserialize_public_key, dilithium_deserialize_secret_key,
    dilithium_deserialize_signature, dilithium_keypair, dilithium_serialize_public_key,
    dilithium_serialize_secret_key, dilithium_serialize_signature, dilithium_sign,
    dilithium_verify, DilithiumKeyPair, DilithiumPublicKey, DilithiumSecretKey, DilithiumSignature,
    D_PARAM_NAME, PUBLICKEY_BYTES as DILITHIUM_PUB_BYTES, SECRETKEY_BYTES as DILITHIUM_SK_BYTES,
    SIGNATURE_BYTES as DILITHIUM_SIG_BYTES,
};
