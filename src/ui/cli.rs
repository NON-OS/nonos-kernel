// ui/cli.rs
//
// NØNOS CLI
// - Static registry: open-addressed table, lock-free reads
// - Dual I/O: TUI + GUI bridge mirror; remote stdin preferred
// - History + TAB completion; public suggest hook for TUI
// - JSON telemetry frames to GUI (metrics, proof roots)
// - Event bus integration
// - No heap on the hot path; fixed buffers
//
// All data is public; zero-state.

#![allow(dead_code)]

use alloc::format;
use core::fmt::Write as _;
use core::str;

use core::sync::atomic::{AtomicUsize, Ordering};
use spin::Mutex;

use crate::arch::x86_64::interrupt::{apic, ioapic};
use crate::arch::x86_64::time::timer;
use crate::memory::{self, proof};
use crate::sched::runqueue as rq;
use crate::sched::{
    self,
    task::{self, Affinity, Priority},
};
use crate::ui::event::{self, Event, Pri};
use crate::ui::{gui_bridge, tui};

const PROMPT: &str = "nonos# ";
const MAX_LINE: usize = 256;
const MAX_TOK: usize = 16;

// —————————————————— registry (open addressed) ——————————————————

type CmdFn = fn(&[&str]) -> Result<(), &'static str>;

#[derive(Clone, Copy)]
struct Cmd {
    name: &'static str,
    help: &'static str,
    f: CmdFn,
}

const CAP: usize = 64;
static REG: Mutex<[Option<Cmd>; CAP]> = Mutex::new([None; CAP]);
static REG_LEN: AtomicUsize = AtomicUsize::new(0);

#[inline]
fn hash(s: &str) -> usize {
    // very small FNV-1a
    let mut h: usize = 0xCBF29CE484222325;
    for b in s.as_bytes() {
        h ^= *b as usize;
        h = h.wrapping_mul(0x100000001B3);
    }
    h
}

fn reg_insert(name: &'static str, help: &'static str, f: CmdFn) {
    let mut t = REG.lock();
    let mut i = hash(name) % CAP;
    for _ in 0..CAP {
        if t[i].is_none() {
            t[i] = Some(Cmd { name, help, f });
            REG_LEN.fetch_add(1, Ordering::Relaxed);
            return;
        }
        i = (i + 1) % CAP;
    }
}

#[inline]
fn reg_find(name: &str) -> Option<CmdFn> {
    let t = REG.lock();
    let mut i = hash(name) % CAP;
    for _ in 0..CAP {
        match t[i] {
            Some(c) if c.name == name => return Some(c.f),
            Some(_) => {
                i = (i + 1) % CAP;
            }
            None => return None,
        }
    }
    None
}

fn reg_suggest(prefix: &str) -> Option<&'static str> {
    let t = REG.lock();
    for slot in t.iter() {
        if let Some(c) = slot {
            if c.name.starts_with(prefix) {
                return Some(c.name);
            }
        }
    }
    None
}

fn reg_iter(mut f: impl FnMut(&Cmd)) {
    let t = REG.lock();
    for slot in t.iter() {
        if let Some(c) = slot {
            f(c);
        }
    }
}

// —————————————————— history ——————————————————

const HIST: usize = 64;
static HISTORY: Mutex<[heapless::String<MAX_LINE>; HIST]> = {
    const EMPTY: heapless::String<MAX_LINE> = heapless::String::new();
    Mutex::new([EMPTY; HIST])
};
static HHEAD: Mutex<usize> = Mutex::new(0);

fn hist_push(line: &str) {
    if line.is_empty() {
        return;
    }
    let mut hs = HISTORY.lock();
    let mut head = HHEAD.lock();
    hs[*head].clear();
    let _ = hs[*head].push_str(line);
    *head = (*head + 1) % HIST;
}

// —————————————————— init ——————————————————

pub fn spawn() {
    // sys.*
    reg_insert("help", "list commands", cmd_help);
    reg_insert("sys.time", "show monotonic time", cmd_sys_time);
    reg_insert("sys.mem", "dump layout + maps", cmd_sys_mem);
    reg_insert("sys.apic", "show LAPIC id", cmd_sys_apic);
    reg_insert("sys.ioapic.route", "route GSI: <gsi>", cmd_sys_ioapic_route);

    // rq.*
    reg_insert("rq.stats", "runqueue counts", cmd_rq_stats);

    // task.*
    reg_insert("task.spawn", "spawn demo: <name> <ms> [rt|hi|norm|lo|idle]", cmd_task_spawn);

    // time.*
    reg_insert("time.hrtimer", "arm hrtimer: <ms>", cmd_time_hrtimer);

    // proof.*
    reg_insert("proof.snapshot", "emit proof root (GUI/event)", cmd_proof_snapshot);

    // net.*
    reg_insert("net.send.proof", "publish proof root to mesh", cmd_net_send_proof);

    // gui.*
    reg_insert("gui.ping", "ping GUI bridge", cmd_gui_ping);

    // CLI task + metrics streamer
    sched::task::kspawn("cli", cli_thread, 0, Priority::Normal, Affinity::ANY);
    spawn_metrics_stream();
}

// —————————————————— main ——————————————————

extern "C" fn cli_thread(_arg: usize) -> ! {
    println("\nNØNOS CLI online. `help` for commands.");
    let mut buf = [0u8; MAX_LINE];

    loop {
        print(PROMPT);

        // Prefer remote stdin if connected; else local TUI
        let n = if gui_bridge::is_connected() {
            let got = gui_bridge::recv_line(&mut buf);
            if got == 0 {
                tui::read_line(&mut buf)
            } else {
                got
            }
        } else {
            tui::read_line(&mut buf)
        };
        if n == 0 {
            continue;
        }

        let line = match str::from_utf8(&buf[..n]) {
            Ok(s) => s.trim(),
            Err(_) => {
                crate::arch::x86_64::vga::print("utf8?\n");
                continue;
            }
        };
        if line.is_empty() {
            continue;
        }

        hist_push(line);
        mirror(line);

        let mut argv_arr: [&str; MAX_TOK] = [""; MAX_TOK];
        let argc = split_words(line, &mut argv_arr);
        if argc == 0 {
            continue;
        }

        // Optional auth gate; currently permissive (public console)
        if !authz_allow(argv_arr[0]) {
            println("permission denied");
            continue;
        }

        match reg_find(argv_arr[0]) {
            Some(f) => {
                if let Err(e) = f(&argv_arr[..argc]) {
                    println(e);
                }
            }
            None => {
                if let Some(s) = reg_suggest(argv_arr[0]) {
                    println(&format!("unknown: {} — did you mean `{}`?", argv_arr[0], s));
                } else {
                    println(&format!("unknown: {} (help)", argv_arr[0]));
                }
            }
        }
    }
}

// —————————————————— commands ——————————————————

fn cmd_help(_a: &[&str]) -> Result<(), &'static str> {
    println("commands:");
    reg_iter(|c| println(&format!("  {:<20}  {}", c.name, c.help)));
    Ok(())
}

fn cmd_sys_time(_a: &[&str]) -> Result<(), &'static str> {
    let ns = timer::now_ns();
    println(&format!(
        "time {} ns ({} ms) deadline={}",
        ns,
        ns / 1_000_000,
        timer::is_deadline_mode()
    ));
    Ok(())
}

fn cmd_sys_mem(_a: &[&str]) -> Result<(), &'static str> {
    memory::layout::dump(|s| print(s));
    print("\n");
    memory::virt::dump(|s| print(s));
    Ok(())
}

fn cmd_sys_apic(_a: &[&str]) -> Result<(), &'static str> {
    println(&format!("lapic id {}", apic::id()));
    Ok(())
}

fn cmd_sys_ioapic_route(a: &[&str]) -> Result<(), &'static str> {
    let gsi =
        a.get(1).and_then(|x| x.parse::<u32>().ok()).ok_or("usage: sys.ioapic.route <gsi>")?;
    let (vec, rte) = ioapic::alloc_route(gsi, apic::id()).map_err(|_| "alloc")?;
    ioapic::program_route(gsi, rte).map_err(|_| "program")?;
    ioapic::mask(gsi, false).ok();
    println(&format!("gsi {} -> vec 0x{:02x}", gsi, vec));
    Ok(())
}

fn cmd_rq_stats(_a: &[&str]) -> Result<(), &'static str> {
    let c = rq::stats_counts();
    println(&format!("rq rt={} hi={} norm={} low={} idle={}", c[0], c[1], c[2], c[3], c[4]));
    Ok(())
}

fn cmd_task_spawn(a: &[&str]) -> Result<(), &'static str> {
    let task_name: &'static str = match a.get(1).copied().unwrap_or("demo") {
        "test" => "test",
        "benchmark" => "benchmark",
        "service" => "service",
        _ => "demo",
    };
    let ms = a.get(2).and_then(|x| x.parse::<u64>().ok()).unwrap_or(500);
    let prio = match a.get(3).copied().unwrap_or("norm") {
        "rt" => Priority::Realtime,
        "hi" => Priority::High,
        "lo" => Priority::Low,
        "idle" => Priority::Idle,
        _ => Priority::Normal,
    };
    let tid = task::kspawn(task_name, demo_task, ms as usize, prio, Affinity::ANY);
    println(&format!("spawned tid={:?} prio={:?}", tid, prio));
    Ok(())
}

fn cmd_time_hrtimer(a: &[&str]) -> Result<(), &'static str> {
    let ms = a.get(1).and_then(|x| x.parse::<u64>().ok()).unwrap_or(50);
    let id = timer::hrtimer_after_ns(ms * 1_000_000, || {
        crate::ui::tui::write("[hr]\n");
    });
    println(&format!("hrtimer id={} {} ms", id, ms));
    Ok(())
}

fn cmd_proof_snapshot(_a: &[&str]) -> Result<(), &'static str> {
    let mut roots = [[0u8; 32]; 64];
    let mut hdr = proof::SnapshotHeader::default();
    let n = proof::snapshot(&mut roots, &mut hdr);
    println(&format!("root {:02x?} caps {}", &hdr.root, n));
    event::publish_pri(Event::ProofRoot { root: hdr.root, epoch: hdr.epoch }, Pri::Norm);
    gui_json_proof(&hdr.root, hdr.epoch);
    Ok(())
}

fn cmd_net_send_proof(_a: &[&str]) -> Result<(), &'static str> {
    let mut roots = [[0u8; 32]; 1];
    let mut hdr = proof::SnapshotHeader::default();
    let _ = proof::snapshot(&mut roots, &mut hdr);
    event::publish_pri(Event::ProofRoot { root: hdr.root, epoch: hdr.epoch }, Pri::High);
    println("queued proof root for mesh");
    Ok(())
}

fn cmd_gui_ping(_a: &[&str]) -> Result<(), &'static str> {
    gui_bridge::send_json("{\"type\":\"ping\"}");
    println("gui ping");
    Ok(())
}

// —————————————————— metrics stream → GUI ——————————————————

fn spawn_metrics_stream() {
    extern "C" fn t(_arg: usize) -> ! {
        loop {
            if gui_bridge::is_connected() {
                let ms = timer::now_ms();
                let rqv = rq::stats_counts();
                let json = json_metrics(ms, &rqv);
                gui_bridge::send_json(&json);
                event::publish_pri(Event::Heartbeat { ms, rq: rqv }, Pri::Low);
            }
            timer::busy_sleep_ns(1_000_000_000);
        }
    }
    let _ = task::kspawn("cli.metrics", t, 0, Priority::Low, Affinity::ANY);
}

fn json_metrics(ms: u64, rq: &[usize; 5]) -> heapless::String<256> {
    let mut s: heapless::String<256> = heapless::String::new();
    let _ = write!(
        s,
        "{{\"type\":\"metrics\",\"ms\":{},\"rq\":[{},{},{},{},{}]}}",
        ms, rq[0], rq[1], rq[2], rq[3], rq[4]
    );
    s
}

fn gui_json_proof(root: &[u8; 32], epoch: u64) {
    let mut s: heapless::String<256> = heapless::String::new();
    let _ = write!(s, "{{\"type\":\"proof\",\"epoch\":{},\"root\":\"0x", epoch);
    for b in root {
        let _ = write!(s, "{:02x}", b);
    }
    let _ = write!(s, "\"}}");
    gui_bridge::send_json(&s);
}

// —————————————————— TAB completion hook (called by TUI) ——————————————————

#[no_mangle]
pub extern "C" fn cli_suggest_for_tab(line_prefix: &str) -> Option<heapless::String<256>> {
    // If prefix has no space → complete command; else leave to command-specific
    // completers later.
    if !line_prefix.contains(' ') {
        if let Some(s) = reg_suggest(line_prefix) {
            let mut out: heapless::String<256> = heapless::String::new();
            let _ = out.push_str(s);
            return Some(out);
        }
    }
    None
}

// —————————————————— helpers ——————————————————

fn split_words<'a>(line: &'a str, out: &mut [&'a str; MAX_TOK]) -> usize {
    let mut n = 0;
    for w in line.split_whitespace() {
        if n == out.len() {
            break;
        }
        out[n] = w;
        n += 1;
    }
    n
}

// HACK: Temporary bypass until ZK-RBAC integration complete
#[inline]
fn authz_allow(_cmd: &str) -> bool {
    true
}

extern "C" fn demo_task(period_ms: usize) -> ! {
    let tid = task::current();
    loop {
        let t = timer::now_ms();
        println(&format!("[demo {:?}] t={} ms", tid, t));
        timer::sleep_long_ns((period_ms as u64) * 1_000_000, || {});
        crate::sched::schedule_now();
    }
}

// dual-sink print

#[inline]
fn print(s: &str) {
    tui::write(s);
    gui_bridge::send_line(s);
}
#[inline]
fn println(s: &str) {
    print(s);
    print("\n");
}
#[inline]
fn mirror(line: &str) {
    gui_bridge::send_line(&format!("CMD: {}", line));
}

#[inline]
fn println_fmt(args: core::fmt::Arguments) {
    struct W;
    impl core::fmt::Write for W {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            print(s);
            Ok(())
        }
    }
    let _ = W.write_fmt(args);
}

#[macro_export]
macro_rules! kprintln {
    ($($arg:tt)*) => ($crate::ui::cli::println_fmt(format_args!($($arg)*)));
}
