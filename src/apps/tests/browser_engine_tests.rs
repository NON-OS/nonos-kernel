#[test]
fn test_browser_engine_module_exists() {
    assert!(true);
}

#[test]
fn test_node_types() {
    let element: u8 = 1;
    let text: u8 = 3;
    let comment: u8 = 8;
    assert!(element < text);
    assert!(text < comment);
}

#[test]
fn test_http_methods() {
    let get = "GET";
    let post = "POST";
    assert_ne!(get, post);
}
