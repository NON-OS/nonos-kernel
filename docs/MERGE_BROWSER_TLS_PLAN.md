# Merge Conflict Resolution Plan: Browser/TLS Feature Integration

## Context
- Local branch: 11 feature commits (browser TLS 1.3, HTTP pooling, Brotli, JPEG, async image pipeline, no-JS forms)
- Remote `origin/main`: 258 commits (UI, settings, keyboard, backgrounds, privacy, etc.)
- 3 merge conflicts: 
  - `src/apps/ecosystem/browser/engine/mod.rs`
  - `src/apps/ecosystem/browser/engine/render/context.rs`
  - `src/network/onion/tls/connection/app.rs`

## Goals
- Integrate local browser/TLS feature work on top of latest `origin/main`
- Resolve all conflicts with full intent preserved
- Maintain kernel safety, security, and codebase conventions
- Ensure all tests and boot scenarios pass after merge

---

## Step-by-Step Plan

### 1. Safety Net
- [ ] Create backup of current local `main` branch
- [ ] Ensure all local changes are committed

### 2. Prepare Integration Branch
- [ ] Fetch latest `origin/main`
- [ ] Create new branch from `origin/main` (e.g., `browser-tls-feature`)

### 3. Cherry-pick Local Commits
- [ ] Cherry-pick all 11 local commits onto new branch
- [ ] Resolve conflicts as they appear (see below for file-specific strategy)

### 4. Conflict Resolution Checklist
#### a. `engine/mod.rs`
- [ ] Merge both sides' changes to `pub use` lines
- [ ] Ensure all required re-exports for local features are present
- [ ] Remove unused re-exports if not needed by new code

#### b. `render/context.rs`
- [ ] Merge visibility tightening (`pub(super)`) from remote
- [ ] Remove `ListCtx` and `list_stack` per remote
- [ ] Add/keep new fields (`base_url`, `form_action`, `form_method`) and constructor param
- [ ] Ensure `new()` signature is correct and all call sites updated

#### c. `tls/connection/app.rs`
- [ ] Use local deadline-based handshake loop
- [ ] Integrate remote's `yield_now()` for cooperative waiting
- [ ] Ensure all new session resumption and post-handshake logic is present
- [ ] Double-check for security invariants and correct error handling

### 5. Verification
- [ ] Build kernel (`make`)
- [ ] Run all host tests (`cargo test --features std`)
- [ ] Boot in QEMU (`make run-serial`)
- [ ] Manually test browser/TLS features (image loading, form submission, session resumption)
- [ ] Review diffs for accidental loss of remote-side bugfixes

### 6. Finalize
- [ ] If all tests pass, fast-forward `main` to new branch
- [ ] Delete backup and feature branches
- [ ] Document merge in commit message and internal changelog

---

## Notes
- If any step fails, revert to backup and debug incrementally
- For each conflict, prefer explicit code comments explaining why a resolution was chosen
- If unsure about a remote-side change, consult commit history or relevant contributors
- All changes must pass clippy and formatting checks

---

## Progress Checklist
- [ ] Safety net created
- [ ] Integration branch created
- [ ] Local commits cherry-picked
- [ ] All conflicts resolved
- [ ] Kernel builds
- [ ] Tests pass
- [ ] QEMU boots
- [ ] Manual feature verification
- [ ] Main branch updated
- [ ] Documentation updated
