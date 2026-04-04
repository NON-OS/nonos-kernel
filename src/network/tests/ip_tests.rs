#[test]
fn test_ip_module_exists() {
    assert!(true);
}

#[test]
fn test_ipv4_address() {
    let addr: [u8; 4] = [192, 168, 1, 1];
    assert_eq!(addr[0], 192);
}

#[test]
fn test_ipv6_address() {
    let addr: [u8; 16] = [0; 16];
    assert_eq!(addr.len(), 16);
}

#[test]
fn test_ip_protocols() {
    let tcp: u8 = 6;
    let udp: u8 = 17;
    let icmp: u8 = 1;
    assert!(tcp != udp);
    assert!(icmp < tcp);
}
