#![no_std]

/*!
Onion Routing Cryptography

 - Pluggable `CryptoProvider` (X25519, AES-128-CTR, HMAC-SHA256, BLAKE3, HKDF)
 - Tor-compatible ntor-style handshake (client_pub || client_nonce -> server_pub || authenticator)
 - Clean `LayerKeys` with per-direction CTR counters + rolling 4-byte digests (telemetry hint)
 - `OnionCrypto` registry for per-circuit layered transforms

 Integrates with nonos circuit manager and cell layer.
*/

use alloc::{vec, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::{Mutex, Once};

use super::OnionError;

/* ===== Protocol constants (kept for external compatibility) ===== */

pub const TAP_C_HANDSHAKE_LEN: usize = 186; // legacy TAP (not used)
pub const TAP_S_HANDSHAKE_LEN: usize = 148;

pub const NTOR_ONIONSKIN_LEN: usize = 84; // client pubkey(32) + client nonce(32) + pad(20)
pub const NTOR_REPLY_LEN: usize = 64; // server pubkey(32) + authenticator(32)

pub const CELL_PAYLOAD_SIZE: usize = 509;
pub const RELAY_PAYLOAD_SIZE: usize = 498;

pub const KEY_LEN: usize = 16; // AES-128
pub const IV_LEN: usize = 16; // 128-bit nonce/IV for CTR
pub const DIGEST_LEN: usize = 4;

/* ===== Crypto provider abstraction ===== */

/// Implement this trait by forwarding to NONOS crypto primitives.
/// Initialize once with `init_onion_crypto_provider(&Provider)`.
pub trait CryptoProvider: Sync + Send {
    /* Randomness */
    fn random_bytes(&self, out: &mut [u8]) -> Result<(), OnionError>;

    /* Hash */
    fn blake3(&self, data: &[u8], out32: &mut [u8; 32]);

    /* MAC/KDF */
    fn hmac_sha256(&self, key: &[u8], data: &[u8], out32: &mut [u8; 32]);
    fn hkdf_sha256_expand(&self, prk: &[u8; 32], info: &[u8], out: &mut [u8]);

    /* ECDH (X25519 for ntor) */
    fn x25519_generate_keypair(&self) -> Result<([u8; 32], [u8; 32]), OnionError>;
    fn x25519(&self, sk: &[u8; 32], pk: &[u8; 32]) -> Result<[u8; 32], OnionError>;

    /* Stream cipher (AES-128-CTR). If you prefer ChaCha20, provide the same API
     * semantics. */
    /// Apply keystream for `inout` starting at CTR = `counter`, then increment
    /// internal block ctr accordingly.
    fn aes128_ctr_apply(&self, key: &[u8; 16], iv: &[u8; 16], counter: u128, inout: &mut [u8]);

    /* Optional constant-time compare fallback */
    fn ct_eq(&self, a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        let mut acc = 0u8;
        for i in 0..a.len() {
            acc |= a[i] ^ b[i];
        }
        acc == 0
    }
}

static CRYPTO: Once<&'static dyn CryptoProvider> = Once::new();

pub fn init_onion_crypto_provider(p: &'static dyn CryptoProvider) {
    CRYPTO.call_once(|| p);
}

#[inline]
fn provider() -> &'static dyn CryptoProvider {
    *CRYPTO.get().expect("Onion CryptoProvider not initialized")
}

/* ===== Layered keys (per-hop) ===== */

#[derive(Debug, Clone)]
pub struct LayerKeys {
    pub forward_key: [u8; KEY_LEN],
    pub backward_key: [u8; KEY_LEN],
    pub forward_iv: [u8; IV_LEN],
    pub backward_iv: [u8; IV_LEN],
    pub forward_digest: [u8; DIGEST_LEN],
    pub backward_digest: [u8; DIGEST_LEN],
    // internal CTR counters (block count from IV start) for each direction
    fwd_ctr_blocks: u128,
    bwd_ctr_blocks: u128,
}

impl LayerKeys {
    /// Create new LayerKeys from raw key material
    pub fn new(
        forward_key: [u8; KEY_LEN],
        backward_key: [u8; KEY_LEN],
        forward_iv: [u8; IV_LEN],
        backward_iv: [u8; IV_LEN],
        forward_digest: [u8; DIGEST_LEN],
        backward_digest: [u8; DIGEST_LEN],
    ) -> Self {
        Self {
            forward_key,
            backward_key,
            forward_iv,
            backward_iv,
            forward_digest,
            backward_digest,
            fwd_ctr_blocks: 0,
            bwd_ctr_blocks: 0,
        }
    }

    /// Encrypt forward (client -> exit). Stateless caller API; CTR state
    /// carried in `self`.
    pub fn encrypt_forward(&mut self, data: &[u8]) -> Result<Vec<u8>, OnionError> {
        let mut out = data.to_vec();
        if !out.is_empty() {
            provider().aes128_ctr_apply(
                &self.forward_key,
                &self.forward_iv,
                self.fwd_ctr_blocks,
                &mut out,
            );
            self.bump_forward(&out);
        }
        Ok(out)
    }

    /// Decrypt backward (exit -> client). CTR decrypt == encrypt.
    pub fn decrypt_backward(&mut self, data: &[u8]) -> Result<Vec<u8>, OnionError> {
        let mut out = data.to_vec();
        if !out.is_empty() {
            provider().aes128_ctr_apply(
                &self.backward_key,
                &self.backward_iv,
                self.bwd_ctr_blocks,
                &mut out,
            );
            self.bump_backward(&out);
        }
        Ok(out)
    }

    #[inline]
    fn bump_forward(&mut self, ciphertext: &[u8]) {
        let mut h = [0u8; 32];
        provider().blake3(ciphertext, &mut h);
        self.forward_digest.copy_from_slice(&h[..DIGEST_LEN]);
        self.fwd_ctr_blocks =
            self.fwd_ctr_blocks.saturating_add(((ciphertext.len() + 15) / 16) as u128);
    }

    #[inline]
    fn bump_backward(&mut self, plaintext: &[u8]) {
        let mut h = [0u8; 32];
        provider().blake3(plaintext, &mut h);
        self.backward_digest.copy_from_slice(&h[..DIGEST_LEN]);
        self.bwd_ctr_blocks =
            self.bwd_ctr_blocks.saturating_add(((plaintext.len() + 15) / 16) as u128);
    }

    /// Construct from a completed `HopCrypto`.
    pub fn from_hop_crypto(hc: &HopCrypto) -> Self {
        let mut lk = LayerKeys {
            forward_key: [0u8; KEY_LEN],
            backward_key: [0u8; KEY_LEN],
            forward_iv: [0u8; IV_LEN],
            backward_iv: [0u8; IV_LEN],
            forward_digest: [0u8; DIGEST_LEN],
            backward_digest: [0u8; DIGEST_LEN],
            fwd_ctr_blocks: 0,
            bwd_ctr_blocks: 0,
        };
        lk.forward_key.copy_from_slice(&hc.forward_key[..KEY_LEN]);
        lk.backward_key.copy_from_slice(&hc.backward_key[..KEY_LEN]);
        lk.forward_iv.copy_from_slice(&hc.forward_iv[..IV_LEN]);
        lk.backward_iv.copy_from_slice(&hc.backward_iv[..IV_LEN]);
        lk
    }
}

/* ===== Handshake (ntor-like) ===== */

#[derive(Debug, Clone, PartialEq)]
pub enum HandshakeState {
    Initial,
    Sent,
    Complete,
    Failed,
}

/// Per-hop handshake state. Produces symmetric `LayerKeys` material when
/// complete.
#[derive(Debug)]
pub struct HopCrypto {
    pub forward_key: Vec<u8>,
    pub backward_key: Vec<u8>,
    pub forward_iv: Vec<u8>,
    pub backward_iv: Vec<u8>,

    handshake_state: HandshakeState,

    // x25519 keypair
    sk: [u8; 32],
    pk: [u8; 32],

    // peer values learned at completion
    server_pk: Option<[u8; 32]>,
    shared_secret: Option<[u8; 32]>,

    // client nonce for binding/auth
    client_nonce: [u8; 32],
}

impl HopCrypto {
    /// `relay_onion_key` is the relay's X25519 (ntor) public key (32 bytes).
    pub fn new(relay_onion_key: &[u8]) -> Result<Self, OnionError> {
        if relay_onion_key.len() != 32 {
            return Err(OnionError::CryptoError);
        }
        let (sk, pk) = provider().x25519_generate_keypair()?;
        let mut nonce = [0u8; 32];
        provider().random_bytes(&mut nonce)?;

        Ok(Self {
            forward_key: vec![0u8; KEY_LEN],
            backward_key: vec![0u8; KEY_LEN],
            forward_iv: vec![0u8; IV_LEN],
            backward_iv: vec![0u8; IV_LEN],
            handshake_state: HandshakeState::Initial,
            sk,
            pk,
            server_pk: None,
            shared_secret: None,
            client_nonce: nonce,
        })
    }

    /// Client -> Relay: client_pub(32) || client_nonce(32) || pad(20)
    /// Call exactly once; moves state to `Sent`.
    pub fn handshake_data(&mut self) -> Vec<u8> {
        if self.handshake_state != HandshakeState::Initial {
            return Vec::new();
        }
        let mut out = Vec::with_capacity(NTOR_ONIONSKIN_LEN);
        out.extend_from_slice(&self.pk);
        out.extend_from_slice(&self.client_nonce);
        let mut pad = [0u8; NTOR_ONIONSKIN_LEN - 64];
        let _ = provider().random_bytes(&mut pad);
        out.extend_from_slice(&pad);
        self.handshake_state = HandshakeState::Sent;
        out
    }

    /// Relay -> Client: server_pub(32) || authenticator(32)
    ///
    /// Authenticator = HMAC-SHA256( DH(shared), "ntor-auth" || client_nonce ||
    /// server_pub || client_pub )
    pub fn complete_handshake(&mut self, response: &[u8]) -> Result<(), OnionError> {
        if self.handshake_state != HandshakeState::Sent {
            return Err(OnionError::CryptoError);
        }
        if response.len() < NTOR_REPLY_LEN {
            return Err(OnionError::InvalidCell);
        }

        let mut spk = [0u8; 32];
        spk.copy_from_slice(&response[..32]);
        let mut tag = [0u8; 32];
        tag.copy_from_slice(&response[32..64]);

        // ECDH
        let shared = provider().x25519(&self.sk, &spk)?;
        self.server_pk = Some(spk);
        self.shared_secret = Some(shared);

        // Verify server authenticator
        let mut auth_msg = Vec::with_capacity(6 + 32 + 32 + 32);
        auth_msg.extend_from_slice(b"ntor-auth");
        auth_msg.extend_from_slice(&self.client_nonce);
        auth_msg.extend_from_slice(&spk);
        auth_msg.extend_from_slice(&self.pk);
        let mut expect = [0u8; 32];
        provider().hmac_sha256(shared.as_slice(), &auth_msg, &mut expect);
        if !provider().ct_eq(&expect, &tag) {
            self.handshake_state = HandshakeState::Failed;
            return Err(OnionError::CryptoError);
        }

        // Derive traffic keys via HKDF-Expand
        // PRK = HMAC(shared, "ntor-prk")
        let mut prk = [0u8; 32];
        provider().hmac_sha256(shared.as_slice(), b"ntor-prk", &mut prk);

        // info = "NONOS_ONION_KDF" || client_nonce || server_pub || client_pub
        let mut info = Vec::with_capacity(16 + 32 + 32 + 32);
        info.extend_from_slice(b"NONOS_ONION_KDF");
        info.extend_from_slice(&self.client_nonce);
        info.extend_from_slice(&spk);
        info.extend_from_slice(&self.pk);

        const OUT_LEN: usize = KEY_LEN * 2 + IV_LEN * 2;
        let mut okm = [0u8; OUT_LEN];
        provider().hkdf_sha256_expand(&prk, &info, &mut okm);

        self.forward_key.copy_from_slice(&okm[0..KEY_LEN]);
        self.backward_key.copy_from_slice(&okm[KEY_LEN..KEY_LEN * 2]);
        self.forward_iv.copy_from_slice(&okm[KEY_LEN * 2..KEY_LEN * 2 + IV_LEN]);
        self.backward_iv.copy_from_slice(&okm[KEY_LEN * 2 + IV_LEN..KEY_LEN * 2 + IV_LEN * 2]);

        self.handshake_state = HandshakeState::Complete;
        Ok(())
    }

    pub fn is_complete(&self) -> bool {
        self.handshake_state == HandshakeState::Complete
    }
}

/* ===== OnionCrypto (per-circuit onion layering) ===== */

#[derive(Debug)]
pub struct OnionCrypto {
    circuits: Mutex<alloc::collections::BTreeMap<u32, Vec<LayerKeys>>>,
    operation_count: AtomicU64,
}

impl Clone for OnionCrypto {
    fn clone(&self) -> Self {
        Self {
            circuits: Mutex::new(alloc::collections::BTreeMap::new()),
            operation_count: AtomicU64::new(
                self.operation_count.load(core::sync::atomic::Ordering::Relaxed),
            ),
        }
    }
}

impl OnionCrypto {
    pub fn new() -> Self {
        Self {
            circuits: Mutex::new(alloc::collections::BTreeMap::new()),
            operation_count: AtomicU64::new(0),
        }
    }

    /// Register/replace the full set of layer keys for a circuit.
    pub fn add_circuit(&self, circuit_id: u32, layers: Vec<LayerKeys>) {
        let mut map = self.circuits.lock();
        map.insert(circuit_id, layers);
    }

    /// Encrypt forward across all layers: apply exit -> middle -> guard.
    pub fn encrypt_forward(&self, circuit_id: u32, data: &[u8]) -> Result<Vec<u8>, OnionError> {
        let mut map = self.circuits.lock();
        if let Some(layers) = map.get_mut(&circuit_id) {
            let mut buf = data.to_vec();
            for layer in layers.iter_mut().rev() {
                buf = layer.encrypt_forward(&buf)?;
            }
            self.operation_count.fetch_add(1, Ordering::Relaxed);
            Ok(buf)
        } else {
            Err(OnionError::CircuitBuildFailed)
        }
    }

    /// Decrypt backward across all layers: remove guard -> middle -> exit.
    pub fn decrypt_backward(&self, circuit_id: u32, data: &[u8]) -> Result<Vec<u8>, OnionError> {
        let mut map = self.circuits.lock();
        if let Some(layers) = map.get_mut(&circuit_id) {
            let mut buf = data.to_vec();
            for layer in layers.iter_mut() {
                buf = layer.decrypt_backward(&buf)?;
            }
            self.operation_count.fetch_add(1, Ordering::Relaxed);
            Ok(buf)
        } else {
            Err(OnionError::CircuitBuildFailed)
        }
    }

    /// Total number of layered crypto operations executed (telemetry).
    pub fn get_stats(&self) -> u64 {
        self.operation_count.load(Ordering::Relaxed)
    }
}
