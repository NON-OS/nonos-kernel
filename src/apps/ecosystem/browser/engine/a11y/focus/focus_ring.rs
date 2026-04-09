pub struct FocusRing {
    pub visible: bool,
    pub color: u32,
    pub width: u32,
    pub offset: i32,
}

impl FocusRing {
    pub fn default_ring() -> Self {
        Self { visible: true, color: 0xFF1A_73E8, width: 2, offset: 2 }
    }

    pub fn hidden() -> Self {
        Self { visible: false, color: 0, width: 0, offset: 0 }
    }
}
