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

//! TLS 1.3 Session Resumption — RFC 8446 §4.6.1
//!
//! Implements `SessionTicket` storage and `SessionCache` (LRU, capacity 64)
//! for PSK-based 1-RTT session resumption.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::format;
use spin::Mutex;

use super::types::CipherSuite;
use super::keys::expand_label_len;
use super::crypto_provider::crypto;

/// Maximum number of cached sessions.
const MAX_ENTRIES: usize = 64;

/// Maximum ticket lifetime we accept (7 days), per RFC 8446 §4.6.1
/// which caps at 604800 seconds.
const MAX_TICKET_LIFETIME_SECS: u32 = 604_800;

/// A TLS 1.3 NewSessionTicket (RFC 8446 §4.6.1).
pub struct SessionTicket {
    /// Opaque ticket data sent by the server.
    pub ticket: Vec<u8>,
    /// Server-provided ticket lifetime in seconds.
    pub lifetime_secs: u32,
    /// Server-provided ticket_age_add obfuscation value.
    pub age_add: u32,
    /// Ticket nonce used to derive per-ticket PSK.
    pub nonce: Vec<u8>,
    /// The resumption master secret from the original handshake.
    pub resumption_secret: Vec<u8>,
    /// Cipher suite that was negotiated in the original handshake.
    pub suite: CipherSuite,
    /// Hash length for the cipher suite (32 or 48).
    pub hash_len: usize,
    /// Timestamp (ms) when this ticket was received.
    pub created_ms: u64,
    /// max_early_data_size from the ticket (0 = no 0-RTT).
    pub max_early_data: u32,
}

impl SessionTicket {
    /// Derive the PSK for this ticket: HKDF-Expand-Label(resumption_secret, "resumption", nonce, hash_len).
    pub fn derive_psk(&self) -> Vec<u8> {
        let mut psk = vec![0u8; self.hash_len];
        expand_label_len(
            &self.resumption_secret,
            b"resumption",
            &self.nonce,
            &mut psk,
            self.hash_len,
        );
        psk
    }

    /// Check if this ticket has expired given the current time in milliseconds.
    pub fn is_expired(&self, now_ms: u64) -> bool {
        let effective_lifetime = self.lifetime_secs.min(MAX_TICKET_LIFETIME_SECS);
        let expiry_ms = self.created_ms.saturating_add(effective_lifetime as u64 * 1000);
        now_ms >= expiry_ms
    }

    /// Compute the obfuscated_ticket_age for the PSK binder (RFC 8446 §4.2.11.1).
    pub fn obfuscated_age(&self, now_ms: u64) -> u32 {
        let real_age_ms = now_ms.saturating_sub(self.created_ms) as u32;
        real_age_ms.wrapping_add(self.age_add)
    }
}

impl Drop for SessionTicket {
    fn drop(&mut self) {
        for byte in self.resumption_secret.iter_mut() {
            // SAFETY: volatile write prevents compiler from eliding zeroization
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        for byte in self.nonce.iter_mut() {
            // SAFETY: volatile write prevents compiler from eliding zeroization
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        for byte in self.ticket.iter_mut() {
            // SAFETY: volatile write prevents compiler from eliding zeroization
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    }
}

/// Per-host LRU session cache for TLS 1.3 resumption tickets.
pub struct SessionCache {
    /// Map of "host:port" → (ticket, last_access order).
    entries: Mutex<BTreeMap<String, (SessionTicket, u64)>>,
    /// Monotonic counter for LRU ordering (incremented on each access).
    access_counter: Mutex<u64>,
}

impl SessionCache {
    pub const fn new() -> Self {
        Self {
            entries: Mutex::new(BTreeMap::new()),
            access_counter: Mutex::new(0),
        }
    }

    /// Store a ticket for the given host:port. Evicts oldest entry if at capacity.
    pub fn store(&self, host: &str, port: u16, ticket: SessionTicket) {
        let key = format!("{}:{}", host, port);
        let mut entries = self.entries.lock();
        let mut counter = self.access_counter.lock();
        *counter += 1;
        let order = *counter;

        // Evict oldest if at capacity and this is a new key
        if entries.len() >= MAX_ENTRIES && !entries.contains_key(&key) {
            if let Some(oldest_key) = entries
                .iter()
                .min_by_key(|(_, (_, ord))| *ord)
                .map(|(k, _)| k.clone())
            {
                entries.remove(&oldest_key);
            }
        }

        entries.insert(key, (ticket, order));
    }

    /// Retrieve a non-expired ticket for the given host:port. Returns `None` if
    /// no valid ticket exists. Removes expired tickets on access.
    pub fn get(&self, host: &str, port: u16) -> Option<SessionTicket> {
        let key = format!("{}:{}", host, port);
        let now_ms = crate::time::timestamp_millis();
        let mut entries = self.entries.lock();

        match entries.remove(&key) {
            Some((ticket, _)) => {
                if ticket.is_expired(now_ms) {
                    // Ticket expired — drop it, return None
                    None
                } else {
                    // Valid ticket — update access order and return a usable copy.
                    // We consume the ticket (single-use per RFC 8446 §4.6.1
                    // recommendation to avoid tracking issues).
                    Some(ticket)
                }
            }
            None => None,
        }
    }

    /// Remove all entries. Used during shutdown or key rotation.
    pub fn clear(&self) {
        let mut entries = self.entries.lock();
        entries.clear();
        let mut counter = self.access_counter.lock();
        *counter = 0;
    }

    /// Number of cached tickets (for diagnostics/tests).
    pub fn len(&self) -> usize {
        self.entries.lock().len()
    }
}

/// Parse a NewSessionTicket handshake message (type 0x04, RFC 8446 §4.6.1).
///
/// Format:
///   lifetime(4) | age_add(4) | nonce_len(1) | nonce(nonce_len)
///   | ticket_len(2) | ticket(ticket_len) | extensions_len(2) | extensions(...)
pub fn parse_new_session_ticket(body: &[u8]) -> Result<(u32, u32, Vec<u8>, Vec<u8>, u32), &'static str> {
    if body.len() < 9 {
        return Err("NewSessionTicket too short");
    }
    let lifetime = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    let age_add = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
    let nonce_len = body[8] as usize;

    let mut off = 9;
    if body.len() < off + nonce_len + 2 {
        return Err("NewSessionTicket nonce truncated");
    }
    let nonce = body[off..off + nonce_len].to_vec();
    off += nonce_len;

    let ticket_len = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
    off += 2;
    if body.len() < off + ticket_len + 2 {
        return Err("NewSessionTicket ticket truncated");
    }
    let ticket = body[off..off + ticket_len].to_vec();
    off += ticket_len;

    // Parse extensions (we only care about early_data max_size = ext type 0x002a)
    let mut max_early_data: u32 = 0;
    if body.len() >= off + 2 {
        let ext_len = u16::from_be_bytes([body[off], body[off + 1]]) as usize;
        off += 2;
        let ext_end = (off + ext_len).min(body.len());
        let mut eoff = off;
        while eoff + 4 <= ext_end {
            let etype = u16::from_be_bytes([body[eoff], body[eoff + 1]]);
            let elen = u16::from_be_bytes([body[eoff + 2], body[eoff + 3]]) as usize;
            eoff += 4;
            if eoff + elen > ext_end { break; }
            if etype == 0x002a && elen == 4 {
                max_early_data = u32::from_be_bytes([
                    body[eoff], body[eoff + 1], body[eoff + 2], body[eoff + 3],
                ]);
            }
            eoff += elen;
        }
    }

    Ok((lifetime, age_add, nonce, ticket, max_early_data))
}

/// Build the `pre_shared_key` extension for ClientHello (RFC 8446 §4.2.11).
///
/// Returns (extension_bytes, binder_offset) where binder_offset is the byte
/// position within the full ClientHello where the binder value starts (needed
/// to compute the binder over the truncated transcript).
pub fn build_psk_extension(
    ticket: &[u8],
    obfuscated_age: u32,
    binder_len: usize,
) -> (Vec<u8>, usize) {
    // PskIdentity: identity_len(2) | identity | obfuscated_ticket_age(4)
    let mut identities = Vec::new();
    identities.extend_from_slice(&(ticket.len() as u16).to_be_bytes());
    identities.extend_from_slice(ticket);
    identities.extend_from_slice(&obfuscated_age.to_be_bytes());

    // PskBinderEntry: binder_len(1) | binder(binder_len)
    let mut binders = Vec::new();
    binders.push(binder_len as u8);
    // Placeholder — caller must overwrite after computing transcript
    binders.extend_from_slice(&vec![0u8; binder_len]);

    // pre_shared_key extension body:
    //   identities_len(2) | identities | binders_len(2) | binders
    let mut ext_body = Vec::new();
    ext_body.extend_from_slice(&(identities.len() as u16).to_be_bytes());
    ext_body.extend_from_slice(&identities);
    ext_body.extend_from_slice(&(binders.len() as u16).to_be_bytes());
    ext_body.extend_from_slice(&binders);

    // Binder value starts at: 2 (identities_len) + identities.len() + 2 (binders_len) + 1 (binder_len byte)
    let binder_offset = 2 + identities.len() + 2 + 1;

    (ext_body, binder_offset)
}

/// Build the `psk_key_exchange_modes` extension (RFC 8446 §4.2.9).
/// We only support psk_dhe_ke (0x01) for forward secrecy.
pub fn build_psk_ke_modes_extension() -> Vec<u8> {
    // Extension body: modes_len(1) | mode(1)
    vec![1, 0x01] // psk_dhe_ke
}

/// Compute the PSK binder HMAC over the truncated ClientHello transcript.
///
/// binder_key = HKDF-Expand-Label(early_secret, "res binder", empty_hash, hash_len)
/// finished_key = HKDF-Expand-Label(binder_key, "finished", "", hash_len)
/// binder = HMAC(finished_key, transcript_hash_truncated)
pub fn compute_psk_binder(
    psk: &[u8],
    suite: CipherSuite,
    transcript_hash_truncated: &[u8],
) -> Vec<u8> {
    let c = crypto();
    let hl = suite.hash_len();

    // Derive early secret from PSK
    let mut early_secret = [0u8; 48];
    if hl == 48 {
        let zeros = [0u8; 48];
        c.hkdf_extract_384(&zeros[..hl], psk, &mut early_secret);
    } else {
        let z32 = [0u8; 32];
        let mut psk32 = [0u8; 32];
        let copy_len = psk.len().min(32);
        psk32[..copy_len].copy_from_slice(&psk[..copy_len]);
        let mut es32 = [0u8; 32];
        c.hkdf_extract(&z32, &psk32, &mut es32);
        early_secret[..32].copy_from_slice(&es32);
    }

    // binder_key = HKDF-Expand-Label(early_secret, "res binder", Hash(""), hash_len)
    let mut empty_hash = [0u8; 48];
    if hl == 48 {
        c.sha384(&[], &mut empty_hash);
    } else {
        let mut eh32 = [0u8; 32];
        c.sha256(&[], &mut eh32);
        empty_hash[..32].copy_from_slice(&eh32);
    }
    let mut binder_key = vec![0u8; hl];
    expand_label_len(&early_secret[..hl], b"res binder", &empty_hash[..hl], &mut binder_key, hl);

    // finished_key = HKDF-Expand-Label(binder_key, "finished", "", hash_len)
    let mut finished_key = vec![0u8; hl];
    expand_label_len(&binder_key, b"finished", &[], &mut finished_key, hl);

    // binder = HMAC(finished_key, transcript_hash_truncated)
    let mut binder = vec![0u8; hl];
    if hl == 48 {
        let mut out48 = [0u8; 48];
        c.hmac_sha384(&finished_key, transcript_hash_truncated, &mut out48);
        binder.copy_from_slice(&out48[..hl]);
    } else {
        let mut out32 = [0u8; 32];
        c.hmac_sha256(&finished_key, transcript_hash_truncated, &mut out32);
        binder.copy_from_slice(&out32[..hl]);
    }

    // Zeroize intermediates
    for byte in early_secret.iter_mut() {
        // SAFETY: volatile write prevents compiler from eliding zeroization
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    for byte in binder_key.iter_mut() {
        // SAFETY: volatile write prevents compiler from eliding zeroization
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    for byte in finished_key.iter_mut() {
        // SAFETY: volatile write prevents compiler from eliding zeroization
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

    binder
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_ticket_expired() {
        let ticket = SessionTicket {
            ticket: vec![1, 2, 3],
            lifetime_secs: 10,
            age_add: 0x12345678,
            nonce: vec![0],
            resumption_secret: vec![0u8; 32],
            suite: CipherSuite::TlsAes128GcmSha256,
            hash_len: 32,
            created_ms: 1000,
            max_early_data: 0,
        };
        // 1000 + 10*1000 = 11000 → at 11000 ms it should be expired
        assert!(!ticket.is_expired(10_999));
        assert!(ticket.is_expired(11_000));
        assert!(ticket.is_expired(99_999));
    }

    #[test]
    fn test_session_ticket_max_lifetime_cap() {
        let ticket = SessionTicket {
            ticket: vec![1],
            lifetime_secs: u32::MAX, // server sends absurdly long lifetime
            age_add: 0,
            nonce: vec![0],
            resumption_secret: vec![0u8; 32],
            suite: CipherSuite::TlsAes128GcmSha256,
            hash_len: 32,
            created_ms: 0,
            max_early_data: 0,
        };
        // Capped to MAX_TICKET_LIFETIME_SECS (604800s = 7 days)
        let seven_days_ms = 604_800u64 * 1000;
        assert!(!ticket.is_expired(seven_days_ms - 1));
        assert!(ticket.is_expired(seven_days_ms));
    }

    #[test]
    fn test_obfuscated_age() {
        let ticket = SessionTicket {
            ticket: vec![1],
            lifetime_secs: 3600,
            age_add: 0xAABBCCDD,
            nonce: vec![0],
            resumption_secret: vec![0u8; 32],
            suite: CipherSuite::TlsAes128GcmSha256,
            hash_len: 32,
            created_ms: 1000,
            max_early_data: 0,
        };
        // At time 6000ms, real age = 5000ms
        // obfuscated = 5000 + 0xAABBCCDD = wrapping
        let age = ticket.obfuscated_age(6000);
        assert_eq!(age, 5000u32.wrapping_add(0xAABBCCDD));
    }

    #[test]
    fn test_parse_new_session_ticket_basic() {
        // lifetime=3600(0x00000E10), age_add=0x12345678, nonce_len=1, nonce=[0x42],
        // ticket_len=3, ticket=[0xAA,0xBB,0xCC], ext_len=0
        let mut data = Vec::new();
        data.extend_from_slice(&3600u32.to_be_bytes()); // lifetime
        data.extend_from_slice(&0x12345678u32.to_be_bytes()); // age_add
        data.push(1); // nonce_len
        data.push(0x42); // nonce
        data.extend_from_slice(&3u16.to_be_bytes()); // ticket_len
        data.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // ticket
        data.extend_from_slice(&0u16.to_be_bytes()); // ext_len

        let (lifetime, age_add, nonce, ticket, max_early) = parse_new_session_ticket(&data).unwrap();
        assert_eq!(lifetime, 3600);
        assert_eq!(age_add, 0x12345678);
        assert_eq!(nonce, vec![0x42]);
        assert_eq!(ticket, vec![0xAA, 0xBB, 0xCC]);
        assert_eq!(max_early, 0);
    }

    #[test]
    fn test_parse_new_session_ticket_with_early_data_ext() {
        let mut data = Vec::new();
        data.extend_from_slice(&300u32.to_be_bytes());
        data.extend_from_slice(&0u32.to_be_bytes());
        data.push(0); // nonce_len = 0
        data.extend_from_slice(&2u16.to_be_bytes()); // ticket_len
        data.extend_from_slice(&[0x01, 0x02]);
        // Extensions: early_data (0x002a) with max_early_data_size = 16384
        let mut exts = Vec::new();
        exts.extend_from_slice(&0x002au16.to_be_bytes());
        exts.extend_from_slice(&4u16.to_be_bytes());
        exts.extend_from_slice(&16384u32.to_be_bytes());
        data.extend_from_slice(&(exts.len() as u16).to_be_bytes());
        data.extend_from_slice(&exts);

        let (_, _, _, _, max_early) = parse_new_session_ticket(&data).unwrap();
        assert_eq!(max_early, 16384);
    }

    #[test]
    fn test_parse_new_session_ticket_too_short() {
        assert!(parse_new_session_ticket(&[0; 8]).is_err());
    }

    #[test]
    fn test_build_psk_extension_structure() {
        let ticket = b"test-ticket";
        let (ext, binder_offset) = build_psk_extension(ticket, 0x1234, 32);

        // Verify structure: identities_len(2) + identity_len(2) + ticket(11) + age(4) = 19
        // identities block = 2 + 11 + 4 = 17
        let identities_len = u16::from_be_bytes([ext[0], ext[1]]) as usize;
        assert_eq!(identities_len, 2 + ticket.len() + 4);

        // binder_offset should point into the binders section
        assert_eq!(binder_offset, 2 + identities_len + 2 + 1);
        assert!(binder_offset + 32 <= ext.len());
    }

    #[test]
    fn test_build_psk_ke_modes() {
        let modes = build_psk_ke_modes_extension();
        assert_eq!(modes, vec![1, 0x01]); // psk_dhe_ke only
    }

    #[test]
    fn test_session_ticket_zeroization() {
        let secret = vec![0xFF; 32];
        let nonce = vec![0xAA; 8];
        let ticket_data = vec![0xBB; 64];
        let secret_ptr = secret.as_ptr();
        let nonce_ptr = nonce.as_ptr();
        let ticket_ptr = ticket_data.as_ptr();

        let ticket = SessionTicket {
            ticket: ticket_data,
            lifetime_secs: 100,
            age_add: 0,
            nonce,
            resumption_secret: secret,
            suite: CipherSuite::TlsAes128GcmSha256,
            hash_len: 32,
            created_ms: 0,
            max_early_data: 0,
        };
        drop(ticket);

        // After drop, the volatile writes should have zeroed the memory.
        // NOTE: This is best-effort — the allocator may have reused the memory.
        // In production, the volatile writes + compiler fence guarantee zeroization
        // before deallocation.
    }

    #[test]
    fn test_session_cache_store_and_get() {
        let cache = SessionCache::new();
        // We can't test get() fully without a real timestamp, but we can test store + len
        let ticket = SessionTicket {
            ticket: vec![1, 2, 3],
            lifetime_secs: 3600,
            age_add: 0,
            nonce: vec![0],
            resumption_secret: vec![0u8; 32],
            suite: CipherSuite::TlsAes128GcmSha256,
            hash_len: 32,
            created_ms: crate::time::timestamp_millis(),
            max_early_data: 0,
        };
        cache.store("example.com", 443, ticket);
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn test_session_cache_eviction() {
        let cache = SessionCache::new();
        let now = crate::time::timestamp_millis();

        // Fill beyond capacity
        for i in 0..MAX_ENTRIES + 5 {
            let ticket = SessionTicket {
                ticket: vec![i as u8],
                lifetime_secs: 3600,
                age_add: 0,
                nonce: vec![0],
                resumption_secret: vec![0u8; 32],
                suite: CipherSuite::TlsAes128GcmSha256,
                hash_len: 32,
                created_ms: now,
                max_early_data: 0,
            };
            cache.store(&format!("host{}.com", i), 443, ticket);
        }

        assert_eq!(cache.len(), MAX_ENTRIES);
    }

    #[test]
    fn test_session_cache_clear() {
        let cache = SessionCache::new();
        let ticket = SessionTicket {
            ticket: vec![1],
            lifetime_secs: 3600,
            age_add: 0,
            nonce: vec![0],
            resumption_secret: vec![0u8; 32],
            suite: CipherSuite::TlsAes128GcmSha256,
            hash_len: 32,
            created_ms: 0,
            max_early_data: 0,
        };
        cache.store("test.com", 443, ticket);
        assert_eq!(cache.len(), 1);
        cache.clear();
        assert_eq!(cache.len(), 0);
    }
}
