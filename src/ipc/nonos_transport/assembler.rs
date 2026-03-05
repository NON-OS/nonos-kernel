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

//! Stream reassembly.

extern crate alloc;

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;

use super::error::TransportError;
use super::frame::parse_frame;

/// Maximum concurrent streams per assembler
const MAX_CONCURRENT_STREAMS: usize = 256;

/// Stream assembly timeout in milliseconds
const STREAM_TIMEOUT_MS: u64 = 30_000;

/// In-progress stream assembly state
struct StreamAssemblyState {
    /// Expected total frames
    total: u32,
    /// Received frames (indexed by sequence number)
    frames: BTreeMap<u32, Vec<u8>>,
    /// Timestamp when stream started (for timeout)
    started_ms: u64,
    /// From address for validation
    from: String,
}

impl StreamAssemblyState {
    /// Returns the expected total number of frames for this stream
    fn expected_frames(&self) -> u32 {
        self.total
    }

    /// Returns how many frames have been received so far
    fn received_frames(&self) -> usize {
        self.frames.len()
    }

    /// Returns true if all expected frames have been received
    fn is_complete(&self) -> bool {
        self.frames.len() == self.total as usize
    }
}

/// Assembler statistics
struct AssemblerStats {
    frames_received: AtomicU64,
    streams_completed: AtomicU64,
    streams_timed_out: AtomicU64,
    bytes_assembled: AtomicU64,
}

/// Stream assembler for receiving and reassembling framed payloads
pub struct StreamAssembler {
    /// Active streams being assembled
    streams: Mutex<BTreeMap<u64, StreamAssemblyState>>,
    /// Statistics
    stats: AssemblerStats,
}

impl StreamAssembler {
    /// Create a new stream assembler
    pub const fn new() -> Self {
        Self {
            streams: Mutex::new(BTreeMap::new()),
            stats: AssemblerStats {
                frames_received: AtomicU64::new(0),
                streams_completed: AtomicU64::new(0),
                streams_timed_out: AtomicU64::new(0),
                bytes_assembled: AtomicU64::new(0),
            },
        }
    }

    /// Add a frame and return completed payload if stream is complete
    ///
    /// # Arguments
    /// * `data` - Raw frame data including header
    /// * `from` - Source address for validation
    ///
    /// # Returns
    /// * `Ok(Some(payload))` - Stream complete, payload reassembled
    /// * `Ok(None)` - Frame added, waiting for more frames
    /// * `Err(TransportError)` - Parse or validation error
    pub fn add_frame(&self, data: &[u8], from: &str) -> Result<Option<Vec<u8>>, TransportError> {
        let (header, payload) = parse_frame(data)?;

        self.stats.frames_received.fetch_add(1, Ordering::Relaxed);

        // Handle empty EOF (zero-length stream)
        if header.total == 0 && header.is_eof() {
            self.stats.streams_completed.fetch_add(1, Ordering::Relaxed);
            return Ok(Some(Vec::new()));
        }

        let mut streams = self.streams.lock();

        // Check stream limit
        if !streams.contains_key(&header.stream_id) && streams.len() >= MAX_CONCURRENT_STREAMS {
            return Err(TransportError::TooManyStreams {
                count: streams.len(),
                limit: MAX_CONCURRENT_STREAMS,
            });
        }

        // Get or create stream state
        let state = streams.entry(header.stream_id).or_insert_with(|| {
            StreamAssemblyState {
                total: header.total,
                frames: BTreeMap::new(),
                started_ms: crate::time::timestamp_millis(),
                from: String::from(from),
            }
        });

        // Validate source
        if state.from != from {
            // Different source trying to inject frames
            return Err(TransportError::StreamNotFound {
                stream_id: header.stream_id,
            });
        }

        // Check for duplicate
        if state.frames.contains_key(&header.seq) {
            return Err(TransportError::DuplicateFrame {
                stream_id: header.stream_id,
                seq: header.seq,
            });
        }

        // Store frame payload
        state.frames.insert(header.seq, payload.to_vec());

        // Check if complete using the helper method
        if state.is_complete() {
            // Log progress info using helper methods
            let _expected = state.expected_frames();
            let _received = state.received_frames();

            // Reassemble payload
            let mut complete = Vec::new();
            for seq in 0..state.total {
                if let Some(chunk) = state.frames.get(&seq) {
                    complete.extend_from_slice(chunk);
                }
            }

            self.stats.streams_completed.fetch_add(1, Ordering::Relaxed);
            self.stats.bytes_assembled.fetch_add(complete.len() as u64, Ordering::Relaxed);

            streams.remove(&header.stream_id);
            return Ok(Some(complete));
        }

        Ok(None)
    }

    /// Clean up timed-out streams
    pub fn cleanup_timeouts(&self) -> usize {
        let now = crate::time::timestamp_millis();
        let mut streams = self.streams.lock();
        let mut timed_out = Vec::new();

        for (&stream_id, state) in streams.iter() {
            if now.saturating_sub(state.started_ms) > STREAM_TIMEOUT_MS {
                timed_out.push(stream_id);
            }
        }

        let count = timed_out.len();
        for stream_id in timed_out {
            streams.remove(&stream_id);
            self.stats.streams_timed_out.fetch_add(1, Ordering::Relaxed);
        }

        count
    }

    /// Get number of active streams
    pub fn active_streams(&self) -> usize {
        self.streams.lock().len()
    }

    /// Get statistics
    pub fn get_stats(&self) -> (u64, u64, u64, u64) {
        (
            self.stats.frames_received.load(Ordering::Relaxed),
            self.stats.streams_completed.load(Ordering::Relaxed),
            self.stats.streams_timed_out.load(Ordering::Relaxed),
            self.stats.bytes_assembled.load(Ordering::Relaxed),
        )
    }
}

impl Default for StreamAssembler {
    fn default() -> Self {
        Self::new()
    }
}

// Global assembler instance
static GLOBAL_ASSEMBLER: StreamAssembler = StreamAssembler::new();

/// Get the global stream assembler
pub fn get_assembler() -> &'static StreamAssembler {
    &GLOBAL_ASSEMBLER
}
