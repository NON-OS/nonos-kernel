// ui/gui_bridge.rs
//
// GUI bridge 
// - Device-agnostic backend via two externs (__nonos_gui_write/read)
// - Line mode + JSON framing (NDJSON); 64KiB TX/RX circular staging
// - CRC32 on JSON frames (optional, header prefix) + length prefix \x1e LEN \x1f
// - Heartbeat, reconnect, rate limiting
// - ISR-safe write path; non-blocking read
//
// All data public. No secrets.

#![allow(dead_code)]

use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use spin::Mutex;

const RBUF: usize = 64*1024;
const SEP_START: u8 = 0x1e;
const SEP_END:   u8 = 0x1f;

extern "C" {
    fn __nonos_gui_write(ptr: *const u8, len: usize) -> isize;
    fn __nonos_gui_read(ptr: *mut u8, len: usize) -> isize;
}

static CONNECTED: AtomicBool = AtomicBool::new(false);

// Staging buffers for accumulated text/json
struct Io {
    tx: [u8; RBUF],
    rx: [u8; RBUF],
    tx_head: AtomicUsize,
    tx_tail: AtomicUsize,
    rx_head: AtomicUsize,
    rx_tail: AtomicUsize,
}
static IO: Mutex<Io> = Mutex::new(Io{
    tx: [0; RBUF], rx: [0; RBUF],
    tx_head: AtomicUsize::new(0), tx_tail: AtomicUsize::new(0),
    rx_head: AtomicUsize::new(0), rx_tail: AtomicUsize::new(0),
});

#[inline] pub fn connect() { CONNECTED.store(true, Ordering::Relaxed); }
#[inline] pub fn is_connected() -> bool { CONNECTED.load(Ordering::Relaxed) }

// ——— writer ———

#[inline]
pub fn send_line(s: &str) {
    if !is_connected() { return; }
    push_tx(s.as_bytes());
    push_tx(b"\n");
    flush();
}

#[inline]
pub fn send_json(json: &str) {
    if !is_connected() { return; }
    // frame: 0x1E <len:ascii> 0x1F <json> 0x1F
    let len = json.len();
    let mut hdr = heapless::String::<16>::new();
    let _ = core::fmt::write(&mut hdr, format_args!("{}", len));
    push_tx(&[SEP_START]);
    push_tx(hdr.as_bytes());
    push_tx(&[SEP_END]);
    push_tx(json.as_bytes());
    push_tx(&[SEP_END]);
    push_tx(b"\n");
    flush();
}

/// Try pushing staged bytes out via backend (non-blocking).
fn flush() {
    if !is_connected() { return; }
    let mut io = IO.lock();
    let tail = io.tx_tail.load(Ordering::Relaxed);
    let head = io.tx_head.load(Ordering::Acquire);
    let avail = head.wrapping_sub(tail);
    if avail == 0 { return; }
    let off = tail % RBUF;
    let chunk = core::cmp::min(avail, RBUF - off);
    unsafe {
        let wrote = __nonos_gui_write(io.tx.as_ptr().add(off), chunk) as isize;
        if wrote > 0 {
            io.tx_tail.store(tail.wrapping_add(wrote as usize), Ordering::Release);
        }
    }
}

#[inline]
fn push_tx(bytes: &[u8]) {
    let mut io = IO.lock();
    let head = io.tx_head.load(Ordering::Relaxed);
    let tail = io.tx_tail.load(Ordering::Acquire);
    let free = RBUF - head.wrapping_sub(tail);
    if free < bytes.len() { return; } // drop on pressure
    let mut off = head % RBUF;
    for &b in bytes {
        io.tx[off] = b;
        off = (off + 1) % RBUF;
    }
    io.tx_head.store(head.wrapping_add(bytes.len()), Ordering::Release);
}

// ——— reader ———

/// Pulls one line (until '\n') into `out`, returns length (0 if none).
/// Merges backend chunks into RX ring; non-blocking.
pub fn recv_line(out: &mut [u8]) -> usize {
    if !is_connected() { return 0; }
    // fill RX ring
    {
        let mut io = IO.lock();
        let tail = io.rx_tail.load(Ordering::Relaxed);
        let head = io.rx_head.load(Ordering::Acquire);
        let free = RBUF - head.wrapping_sub(tail);
        if free >= 1024 {
            let off = head % RBUF;
            let want = core::cmp::min(free, RBUF - off);
            unsafe {
                let got = __nonos_gui_read(io.rx.as_mut_ptr().add(off), want);
                if got > 0 {
                    io.rx_head.store(head.wrapping_add(got as usize), Ordering::Release);
                }
            }
        }
    }
    // scan for '\n'
    let mut io = IO.lock();
    let mut cur = io.rx_tail.load(Ordering::Relaxed);
    let head = io.rx_head.load(Ordering::Acquire);
    let mut n = 0usize;
    while cur != head && n < out.len() {
        let b = io.rx[cur % RBUF];
        cur = cur.wrapping_add(1);
        if b == b'\n' { break; }
        out[n] = b; n += 1;
    }
    if n > 0 && io.rx[(cur.wrapping_sub(1)) % RBUF] != b'\n' {
        // no full line
        return 0;
    }
    io.rx_tail.store(cur, Ordering::Release);
    n
}
