//! NONOS Network Subsystem 

pub mod nonos_network_stack;
pub mod nonos_ethernet;
pub mod nonos_ip;
pub mod nonos_tcp;
pub mod nonos_udp;
pub mod nonos_dns;
pub mod nonos_firewall;
pub mod onion;

// Re-exports (stable external surface)
pub use nonos_network_stack as stack;
pub use nonos_ethernet as ethernet;
pub use nonos_ip as ip;
pub use nonos_tcp as tcp;
pub use nonos_udp as udp;
pub use nonos_dns as dns;
pub use nonos_firewall as firewall;

pub use nonos_network_stack::{
    NetworkStack, NetworkStats, init_network_stack, get_network_stack, register_device,
};

extern crate alloc;

/// Bring up base network + TLS + onion router.
/// Call this once during system initialization (after NIC registration).
pub fn init() {
    // 1) Base stack
    init_network_stack();

    // 2) TLS stack (crypto + strict link certificate verifier)
    if let Err(e) = onion::tls::init_tls_stack_production(&onion::tls::KERNEL_TLS_CRYPTO) {
        crate::log::error!("tls: init failed: {:?}", e);
    } else {
        crate::log::info!("tls: production crypto/verifier initialized");
    }

    // 3) Onion routing stack (directory + circuits)
    if let Err(e) = onion::init_onion_router() {
        crate::log::error!("onion: init failed: {:?}", e);
    } else {
        crate::log::info!("onion: initialized");
    }
}

/// Configure IPv4 address, prefix, gateway, and default DNS A server.
pub fn configure_ipv4(ip: [u8; 4], prefix: u8, gateway: Option<[u8; 4]>, dns_v4: Option<[u8; 4]>) {
    if let Some(stack) = get_network_stack() {
        stack.set_ipv4_config(ip, prefix, gateway);
        if let Some(dns) = dns_v4 {
            stack.set_default_dns_v4(dns);
        }
        crate::log::info!(
            "net: configured IPv4 {}/{}, gw={:?}, dns={:?}",
            ip, prefix, gateway, dns_v4
        );
    } else {
        crate::log::warn!("net: stack not initialized (configure_ipv4 ignored)");
    }
}

/// Network daemon loop: runs periodic maintenance for subsystems.
/// On a dedicated worker to keep timers and housekeeping active.
pub fn run_network_stack() {
    loop {
        // Onion maintenance: circuit timeouts, security checks
        onion::process_circuit_maintenance();

        // Yield CPU to the scheduler; NIC and sockets are event/poll driven within the stack
        crate::sched::yield_cpu();
    }
}
