# Copilot Instructions

Engineering guidelines for AI-assisted coding in this repo.
These constrain behavior toward correctness and reviewability over speed.

---

## 1. Think Before Coding

Surface ambiguity before touching files.

- State assumptions explicitly before implementing. If uncertain, ask first.
- If multiple valid interpretations exist, name them and ask — don't pick silently.
- If a simpler approach exists, propose it before doing the complex one.
- If something is underspecified, stop and name what is missing.

The bar: a staff engineer should be able to read your plan and immediately spot a wrong assumption.

---

## 2. Simplicity First

Minimum code that satisfies the requirement. Nothing else.

- No features beyond what was asked.
- No abstractions for code used once.
- No added flexibility or configurability not requested.
- No error handling for states that cannot occur at the call site.
- If an implementation is 200 lines and could be 50, rewrite it.

Self-check: "Would a senior engineer call this over-engineered?" If yes, cut it.

---

## 3. Surgical Changes

Touch only what the request requires.

- Do not improve adjacent code, comments, or formatting not related to the change.
- Do not refactor things that are not broken.
- Match existing style exactly, even when you would do it differently.
- When your edits make an import, variable, or function unused — remove it.
- When you notice pre-existing dead code — mention it in the response, do not delete it.

The test: every changed line should trace directly to the user's request.

---

## 4. Coding Standards (this repo)

- **75-line hard limit**: no file touched in a single change may grow by more than 75 lines. If the change needs more, split it into smaller logical commits.
- **Code explains itself**: do not add `//` comments inside function bodies. If a block needs a comment to be understood, rewrite it until it doesn't.
- **No docstrings**: do not add `///` doc comments to existing symbols you did not create.
- **License headers**: preserve existing AGPL headers exactly — do not touch them.
- **No `std`**: this is a `#![no_std]` bare-metal kernel. All code must compile under the custom target.

---

## 5. Goal-Driven Execution

Define verifiable success before starting.

Transform vague requests into checkable goals:

| Request | Goal |
|---|---|
| "Fix the bug" | Write a test that reproduces it, then make it pass |
| "Add validation" | Write tests for invalid inputs, then make them pass |
| "Refactor X" | Tests pass before and after; diff shows no behavior change |

For multi-step work, state the plan first:

```
1. [action] → verify: [check]
2. [action] → verify: [check]
```

---

## 6. Commit Discipline

One commit per logical change.

- Format: `fix(scope): short description` (imperative, lowercase)
- Body: explain *why*, not *what*. Reference issue number on last line.
- Never bundle unrelated fixes in one commit.
- Compile-check (`cargo check --lib --features std --target x86_64-apple-darwin`) must pass before committing.

---

## 7. Security (OWASP awareness)

- Never cast a physical address directly to a virtual pointer — map it through `crate::memory::mmio::map_device_memory` first.
- Never write to MMIO via a raw static — use `core::ptr::write_volatile`.
- Never commit secrets, keys, or generated ZK artifacts.
- Sanitize all data that crosses a trust boundary (user input, network, bootloader handoff).
