use super::arena::DomArena;

pub fn mark_dirty(arena: &mut DomArena) {
    arena.needs_layout = true;
}

pub fn clear_dirty(arena: &mut DomArena) {
    arena.needs_layout = false;
}

pub fn is_dirty(arena: &DomArena) -> bool {
    arena.needs_layout
}
