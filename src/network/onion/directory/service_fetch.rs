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

use alloc::{format, string::String, vec::Vec};
use core::cmp::min;
use core::sync::atomic::Ordering;

use super::consensus::{current_time_s, ipv4_to_string, parse_consensus};
use super::encoding::b64_url_nopad;
use super::microdesc::{max_microdesc_size, parse_microdesc, sha256_of_text, split_microdesc_blobs};
use super::service_core::DirectoryService;
use super::types::{DirectoryAuthority, RelayDescriptor};
use crate::network::get_network_stack;
use crate::network::onion::OnionError;

const MAX_HTTP_BODY_BYTES: usize = 5 * 1024 * 1024;
const MAX_AUTHORITY_TRIES: usize = 6;
const REFRESH_MIN_SECONDS: u64 = 15 * 60;

impl DirectoryService {
    pub fn fetch_consensus(&self) -> Result<(), OnionError> {
        let now = current_time_s();
        let last = self.last_consensus_fetch.load(Ordering::Relaxed);
        if now.saturating_sub(last) < REFRESH_MIN_SECONDS {
            return Ok(());
        }

        let auths = self.authorities.read();
        let mut attempt = 0usize;
        let mut last_err: Option<OnionError> = None;

        let offset = self.secure_random_u64() as usize % auths.len().max(1);
        while attempt < min(auths.len(), MAX_AUTHORITY_TRIES).max(1) {
            let a = &auths[(offset + attempt) % auths.len()];
            self.directory_stats.authorities_contacted.fetch_add(1, Ordering::Relaxed);

            match self.fetch_from_authority(a, "/tor/status-vote/current/consensus") {
                Ok(body) => {
                    match parse_consensus(&body) {
                        Ok(mut c) => {
                            if let Err(e) = self.validate_consensus(&mut c) {
                                self.directory_stats.consensus_parse_errors.fetch_add(1, Ordering::Relaxed);
                                last_err = Some(e);
                                attempt += 1;
                                continue;
                            }
                            self.directory_stats.consensus_fetches.fetch_add(1, Ordering::Relaxed);
                            *self.current_consensus.write() = Some(c);
                            self.last_consensus_fetch.store(now + self.jitter(5), Ordering::Relaxed);
                            self.update_relay_statistics();
                            return Ok(());
                        }
                        Err(e) => {
                            self.directory_stats.consensus_parse_errors.fetch_add(1, Ordering::Relaxed);
                            last_err = Some(e);
                        }
                    }
                }
                Err(e) => { last_err = Some(e); }
            }
            attempt += 1;
        }

        Err(last_err.unwrap_or(OnionError::DirectoryError))
    }

    pub(super) fn ensure_microdescs(&self) -> Result<(), OnionError> {
        let c = self.current_consensus.read();
        let c = c.as_ref().ok_or(OnionError::DirectoryError)?;

        let mut need: Vec<[u8; 32]> = Vec::new();
        {
            let have = self.microdescriptors.read();
            for e in &c.relays {
                if let Some(d) = e.microdesc_sha256 {
                    if !have.contains_key(&d) {
                        need.push(d);
                    }
                }
            }
        }

        if need.is_empty() { return Ok(()); }

        let auths = self.authorities.read();
        let max_md_size = max_microdesc_size();

        for a in auths.iter() {
            let mut path = String::from("/tor/micro/d/");
            const MAX_PER_REQUEST: usize = 25;

            for chunk in need.chunks(MAX_PER_REQUEST) {
                path.truncate("/tor/micro/d/".len());
                for (i, d) in chunk.iter().enumerate() {
                    if i > 0 { path.push('+'); }
                    path.push_str(&b64_url_nopad(&d[..]));
                }

                if let Ok(body) = self.fetch_from_authority(a, &path) {
                    let texts = split_microdesc_blobs(&body);
                    for t in texts {
                        if t.len() > max_md_size { continue; }
                        if let Some(d) = sha256_of_text(&t) {
                            self.microdescriptors.write().insert(d, t);
                        }
                    }
                    self.directory_stats.descriptor_fetches.fetch_add(1, Ordering::Relaxed);
                }
            }
            break;
        }

        self.materialize_relays_from_microdescs()?;
        Ok(())
    }

    pub(super) fn materialize_relays_from_microdescs(&self) -> Result<(), OnionError> {
        let c = self.current_consensus.read();
        let c = c.as_ref().ok_or(OnionError::DirectoryError)?;

        let micro = self.microdescriptors.read();
        let mut out = self.relay_descriptors.write();

        for e in &c.relays {
            let Some(md_sha) = e.microdesc_sha256 else { continue; };
            let Some(text) = micro.get(&md_sha) else { continue; };

            let parsed = parse_microdesc(text).unwrap_or_default();
            if parsed.ntor_key.len() != 32 { continue; }

            let mut ed = [0u8; 32];
            if let Some(x) = e.ed25519_id { ed = x; }

            let rd = RelayDescriptor {
                nickname: e.nickname.clone(),
                identity_digest: e.identity_digest,
                ed25519_identity: ed,
                ntor_onion_key: parsed.ntor_key.to_vec(),
                address: e.address,
                port: e.or_port,
                dir_port: e.dir_port,
                bandwidth: e.measured_bandwidth.unwrap_or(e.bandwidth.unwrap_or(0)),
                measured_bandwidth: e.measured_bandwidth.unwrap_or(0),
                flags: e.flags.clone(),
                fingerprint: e.identity_digest,
                family: parsed.family,
                country_code: String::new(),
                as_number: 0,
                consensus_weight: 0,
                guard_probability: 0.0,
                middle_probability: 0.0,
                exit_probability: 0.0,
                exit_ports: parsed.exit_ports,
            };

            out.insert(e.identity_digest, rd);
        }

        Ok(())
    }

    pub(super) fn fetch_from_authority(&self, authority: &DirectoryAuthority, path: &str) -> Result<Vec<u8>, OnionError> {
        let Some(net) = get_network_stack() else { return Err(OnionError::NetworkError); };

        let req = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}:{}\r\n\
             User-Agent: NONOS/1.0\r\n\
             Accept: */*\r\n\
             Accept-Encoding: identity\r\n\
             Connection: close\r\n\r\n",
            path, ipv4_to_string(authority.address), authority.dir_port
        );

        let resp = net.http_request(authority.address, authority.dir_port, req.as_bytes())
            .map_err(|_| OnionError::NetworkError)?;

        let (status, body) = parse_http_response_bounded(&resp, MAX_HTTP_BODY_BYTES)?;
        if status / 100 != 2 { return Err(OnionError::DirectoryError); }
        Ok(body)
    }

    pub(super) fn fetch_microdesc_for_digest(&self, d: &[u8; 32]) -> Result<(), OnionError> {
        let auths = self.authorities.read();
        let max_md_size = max_microdesc_size();

        for a in auths.iter() {
            let path = {
                let mut s = String::from("/tor/micro/d/");
                s.push_str(&b64_url_nopad(&d[..]));
                s
            };

            if let Ok(body) = self.fetch_from_authority(a, &path) {
                let texts = split_microdesc_blobs(&body);
                for t in texts {
                    if t.len() > max_md_size { continue; }
                    if let Some(d2) = sha256_of_text(&t) {
                        if &d2 == d {
                            self.microdescriptors.write().insert(*d, t);
                            return Ok(());
                        }
                    }
                }
            }
        }
        Err(OnionError::DirectoryError)
    }
}

fn parse_http_response_bounded(resp: &[u8], cap: usize) -> Result<(u16, Vec<u8>), OnionError> {
    if resp.len() < 12 { return Err(OnionError::DirectoryError); }
    let text = core::str::from_utf8(resp).map_err(|_| OnionError::DirectoryError)?;

    let header_end = text.find("\r\n\r\n").ok_or(OnionError::DirectoryError)?;
    let (head, body) = text.split_at(header_end + 4);

    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or("");
    let mut sl = status_line.split_whitespace();
    let http = sl.next().unwrap_or("");
    if !http.starts_with("HTTP/") {
        return Err(OnionError::DirectoryError);
    }
    let code = sl.next().unwrap_or("0").parse::<u16>().unwrap_or(0);

    let mut content_length: Option<usize> = None;
    for h in lines {
        if h.is_empty() { continue; }
        let (k, v) = match h.split_once(':') { Some(x) => x, None => continue };
        if k.eq_ignore_ascii_case("content-length") {
            if let Ok(n) = v.trim().parse::<usize>() {
                content_length = Some(n);
            }
        }
    }

    let mut body_bytes = body.as_bytes().to_vec();
    if let Some(n) = content_length {
        if n > cap { return Err(OnionError::DirectoryError); }
        if n <= body_bytes.len() {
            body_bytes.truncate(n);
        }
    }
    if body_bytes.len() > cap { return Err(OnionError::DirectoryError); }
    Ok((code, body_bytes))
}
