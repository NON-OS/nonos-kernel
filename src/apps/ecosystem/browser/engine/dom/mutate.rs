use super::node::NodeId;
use super::arena::DomArena;

pub fn append_child(arena: &mut DomArena, parent_id: NodeId, child_id: NodeId) {
    detach_from_parent(arena, child_id);

    let last_child = arena.get(parent_id).and_then(|p| p.children.last().copied());

    if let Some(prev_id) = last_child {
        if let Some(prev) = arena.get_mut(prev_id) {
            prev.next_sibling = Some(child_id);
        }
        if let Some(child) = arena.get_mut(child_id) {
            child.prev_sibling = Some(prev_id);
        }
    }

    if let Some(child) = arena.get_mut(child_id) {
        child.parent = Some(parent_id);
        child.next_sibling = None;
    }

    if let Some(parent) = arena.get_mut(parent_id) {
        parent.children.push(child_id);
    }

    arena.needs_layout = true;
}

pub fn remove_child(arena: &mut DomArena, parent_id: NodeId, child_id: NodeId) {
    if let Some(parent) = arena.get_mut(parent_id) {
        parent.children.retain(|c| *c != child_id);
    }
    fix_sibling_links(arena, child_id);
    if let Some(child) = arena.get_mut(child_id) {
        child.parent = None;
        child.prev_sibling = None;
        child.next_sibling = None;
    }
    arena.needs_layout = true;
}

pub fn insert_before(arena: &mut DomArena, parent_id: NodeId, new_id: NodeId, ref_id: NodeId) {
    detach_from_parent(arena, new_id);

    let position = arena.get(parent_id)
        .and_then(|p| p.children.iter().position(|c| *c == ref_id));

    let pos = match position {
        Some(p) => p,
        None => { append_child(arena, parent_id, new_id); return; }
    };

    let prev_of_ref = arena.get(ref_id).and_then(|n| n.prev_sibling);

    if let Some(prev_id) = prev_of_ref {
        if let Some(prev) = arena.get_mut(prev_id) { prev.next_sibling = Some(new_id); }
        if let Some(new_node) = arena.get_mut(new_id) { new_node.prev_sibling = Some(prev_id); }
    }

    if let Some(new_node) = arena.get_mut(new_id) {
        new_node.next_sibling = Some(ref_id);
        new_node.parent = Some(parent_id);
    }
    if let Some(ref_node) = arena.get_mut(ref_id) { ref_node.prev_sibling = Some(new_id); }
    if let Some(parent) = arena.get_mut(parent_id) { parent.children.insert(pos, new_id); }

    arena.needs_layout = true;
}

fn detach_from_parent(arena: &mut DomArena, node_id: NodeId) {
    let parent_id = arena.get(node_id).and_then(|n| n.parent);
    if let Some(pid) = parent_id {
        remove_child(arena, pid, node_id);
    }
}

fn fix_sibling_links(arena: &mut DomArena, node_id: NodeId) {
    let (prev, next) = arena.get(node_id)
        .map(|n| (n.prev_sibling, n.next_sibling))
        .unwrap_or((None, None));
    if let Some(prev_id) = prev {
        if let Some(p) = arena.get_mut(prev_id) { p.next_sibling = next; }
    }
    if let Some(next_id) = next {
        if let Some(n) = arena.get_mut(next_id) { n.prev_sibling = prev; }
    }
}
