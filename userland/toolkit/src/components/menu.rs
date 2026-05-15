#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MenuItem<'a> {
    pub id: u16,
    pub label: &'a [u8],
    pub enabled: bool,
}

pub fn first_enabled(items: &[MenuItem<'_>]) -> Option<u16> {
    let mut i = 0usize;
    while i < items.len() {
        if items[i].enabled {
            return Some(items[i].id);
        }
        i += 1;
    }
    None
}
