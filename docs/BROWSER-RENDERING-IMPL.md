# Browser Rendering — Implementation Plan

**Branch:** `fix/browser-rendering-improvements`  
**Created:** 2026-03-20  
**Status:** In Progress

---

## Master Checklist

### Tier 1 — Critical / Immediate Wins

- [x] **1.1** Fix TLS record reassembly in `https.rs`
  - [x] Add persistent `Vec<u8>` reassembly buffer (`REASSEMBLY_BUF`) behind `spin::Mutex`
  - [x] Prepend leftover bytes from previous poll before parsing
  - [x] Only extract records where `offset + 5 + record_len <= buf.len()`
  - [x] Carry incomplete trailing bytes to next `poll_receive_response` call
  - [x] On connection cleanup, clear the reassembly buffer
  - [x] Verify AEAD nonce stays in sync after buffering (no skip on partial)
  - [ ] Test: multi-chunk TLS records decrypt correctly in sequence
- [x] **1.2** Strip `<script>`, `<style>`, `<noscript>` in parser
  - [x] Add raw-text skip logic in `parse_html()` tag dispatch
  - [x] On encountering opening tag, scan forward to matching `</tag>`
  - [x] Discard all text content between open and close
  - [x] Do not push children to the DOM for these elements
  - [ ] Test: HTML with inline JS/CSS produces no visible text from those blocks
- [x] **1.3** Strip `<head>` content — only render `<body>` children
  - [x] Add `in_head` boolean flag to parser state
  - [x] Set `true` on `<head>`, `false` on `</head>`
  - [x] Skip all node creation while `in_head == true`
  - [x] Preserve `<title>` extraction (already reads raw text to `doc.title`)
  - [ ] Test: `<meta>`, `<link>` tags no longer produce visible text
- [x] **1.4** Handle `<table>/<tr>/<td>/<th>` rendering
  - [x] In `render.rs`: treat `<table>` as block element (line break before/after)
  - [x] Treat `<tr>` as block element (new line per row)
  - [x] Render `<td>`/`<th>` cells separated by tab character (or fixed-width column)
  - [x] `<th>` text rendered bold
  - [x] `<thead>`/`<tbody>`/`<tfoot>` treated as passthrough containers
  - [ ] Test: simple 3×3 table renders as aligned rows

### Tier 2 — Basic Visual Polish

- [x] **2.1** Handle semantic block elements as passthrough
  - [x] `<nav>`, `<header>`, `<footer>`, `<section>`, `<article>`, `<aside>`, `<main>` — treat as `<div>` (block, line break before/after)
  - [x] `<span>` — treat as inline passthrough (no break)
- [x] **2.2** Inline `style="display:none"` support
  - [x] In renderer: parse `style` attribute on elements
  - [x] If `display:none` found, skip node and all children
  - [x] If `visibility:hidden` found, skip node and all children
- [x] **2.3** `<blockquote>` indentation
  - [x] Push indentation level onto a stack when entering `<blockquote>`
  - [x] Add extra left margin (e.g. `+30px`) per nesting level
  - [x] Pop on `</blockquote>`
- [x] **2.4** List item bullet points
  - [x] Track list context: `<ul>` vs `<ol>` with counter
  - [x] `<li>` inside `<ul>` → prepend "• "
  - [x] `<li>` inside `<ol>` → prepend "N. " with incrementing counter
  - [x] Reset counter on `</ol>`
- [x] **2.5** Background colors for `<code>` and headings
  - [x] Add `bg_color: Option<u32>` field to `TextStyle`
  - [x] Set dark-grey background on `<code>` / `<pre>` blocks
  - [x] Render filled rect behind text in the UI draw layer
- [x] **2.6** `<select>` / `<textarea>` basic rendering
  - [x] `<select>` → render as dropdown placeholder showing first `<option>` text
  - [x] `<textarea>` → render as multi-line input box with placeholder

### Tier 3 — Layout Engine Foundations

- [x] **3.1** Block vs. inline layout model
  - [x] Classify each HTML element as block or inline
  - [x] Block elements: force line break before/after
  - [x] Inline elements: flow with text on same line
  - [x] Refactor `render_page` to use layout classification instead of per-tag matching
- [x] **3.2** CSS class-based `display:none`
  - [x] Parse `<style>` blocks in `<head>` for class→property mappings
  - [x] Build simple class→display map
  - [x] Match element `class` attribute against map
  - [x] Skip node + children if `display: none`
- [x] **3.3** Basic `<img>` rendering
  - [x] Fetch image URL via HTTP/HTTPS
  - [x] Decode BMP/PNG dimensions at minimum
  - [x] Render placeholder rectangle with alt text and dimensions
  - [ ] Stretch goal: decode and blit actual pixels for BMP

### Tier 4 — Out of Scope (Not Planned)

- [ ] JavaScript execution
- [ ] CSS cascade / specificity / inheritance
- [ ] Web fonts / font loading
- [ ] Shadow DOM / Web Components
- [ ] Canvas / WebGL / SVG rendering
- [ ] Flexbox / CSS Grid
- [ ] iframe embedding
- [ ] Video / Audio playback

---

## Detailed Implementation Notes

### 1.1 — TLS Record Reassembly

**File:** `src/apps/ecosystem/browser/navigate/https.rs`  
**Function:** `poll_receive_response()` (lines 189–333)

**Problem:** The current code processes each `tcp_poll_receive(8192)` chunk independently. The inner loop (line 270+) parses TLS record headers directly from the received buffer:

```
while offset + 5 <= received.len() {
    let content_type = received[offset];
    let record_len = u16::from_be_bytes([received[offset+3], received[offset+4]]) as usize;
    if offset + 5 + record_len > received.len() {
        break;  // ← DROPS leftover bytes — they're lost forever
    }
    ...
    offset += 5 + record_len;
}
```

When `break` triggers, bytes from `offset..received.len()` are silently discarded. The next TCP read starts mid-record. The code interprets payload bytes as a TLS header, reading garbage content types (`0x24`, `0xDA`) and absurd lengths (`45137`). The decrypt fails, the AEAD nonce advances anyway, and every subsequent record is permanently desynced.

**Fix design:**

```rust
// Module-level persistent buffer
static REASSEMBLY_BUF: spin::Mutex<Vec<u8>> = spin::Mutex::new(Vec::new());

// Inside poll_receive_response(), after tcp_poll_receive returns data:
{
    let mut reasm = REASSEMBLY_BUF.lock();
    reasm.extend_from_slice(&received);

    let mut offset = 0;
    while offset + 5 <= reasm.len() {
        let record_len = u16::from_be_bytes([reasm[offset+3], reasm[offset+4]]) as usize;
        if offset + 5 + record_len > reasm.len() {
            break; // Incomplete — wait for more data
        }
        // Process complete record...
        offset += 5 + record_len;
    }

    // Keep only the incomplete tail
    if offset > 0 {
        reasm.drain(..offset);
    }
}
```

**Key invariant:** `decrypt_app()` is only ever called with a complete TLS record payload. The AEAD nonce only advances on actual decrypt attempts, so no partial-record garbage can desync it.

**Cleanup:** `REASSEMBLY_BUF.lock().clear()` must be called in `cleanup_https()`.

---

### 1.2 — Strip `<script>`, `<style>`, `<noscript>`

**File:** `src/apps/ecosystem/browser/engine/parser.rs`  
**Function:** `parse_html()` — tag dispatch (line 96+)

**Current behavior:** These tags fall through to the `_ => { ... }` default branch, which pushes them as `Element` nodes. Their text children become `TextNode`s and render as visible page content.

**Fix:** Add a match arm before the default case:

```rust
"script" | "style" | "noscript" => {
    // Skip to closing tag — consume all raw text
    let close_tag = format!("</{}>", tag_name);
    while let Some(c) = chars.next() {
        // Accumulate into temp buffer, scan for close_tag pattern
        // When found, break — content is discarded
    }
    // Do NOT push any node to the DOM
}
```

This is similar to the existing `<title>` handler (lines 118–134), which already does raw-text extraction to a closing tag.

---

### 1.3 — Strip `<head>` Content

**File:** `src/apps/ecosystem/browser/engine/parser.rs`

**Fix:** Add `in_head: bool` state variable. Set `true` on `<head>`, `false` on `</head>`. While `in_head`, skip node creation for everything except `<title>` (which is already handled by raw-text extraction at line 118).

---

### 1.4 — Table Rendering

**File:** `src/apps/ecosystem/browser/engine/render.rs`  
**Function:** `render_page()` — tag dispatch

**Approach:**
- `<table>`: push line break, enter "table mode" context
- `<tr>`: start new row (flush current line)
- `<td>` / `<th>`: render cell content, advance `current_x` by fixed column width (e.g., `usable_width / max_columns` or a fixed 150px)
- `<th>`: same as `<td>` but with `bold = true`
- `</tr>`: flush line
- `</table>`: pop table mode, line break

The renderer already tracks `current_x` and flushes lines — cells are just horizontal segments within a row.

---

### 2.2 — Inline `style="display:none"`

**File:** `src/apps/ecosystem/browser/engine/render.rs`

**Approach:** Before processing any element node, check for a `style` attribute:

```rust
if let Some(style_val) = get_attribute(node, "style") {
    let style_lower = style_val.to_ascii_lowercase();
    if style_lower.contains("display:none") || style_lower.contains("display: none") {
        continue; // Skip this node and all children
    }
}
```

This is a lightweight check — no CSS parser needed. Covers the majority of real-world hidden-content patterns.

---

### 2.4 — List Bullet Points

**File:** `src/apps/ecosystem/browser/engine/render.rs`

**Approach:** Add a list context stack:

```rust
enum ListContext { Unordered, Ordered(u32) }
let mut list_stack: Vec<ListContext> = Vec::new();
```

- `<ul>` → push `Unordered`
- `<ol>` → push `Ordered(1)`
- `<li>` → peek stack: if `Unordered` prepend "• ", if `Ordered(n)` prepend "{n}. " and increment
- `</ul>` / `</ol>` → pop stack

---

## Files to Modify

| File | Changes |
|------|---------|
| `src/apps/ecosystem/browser/navigate/https.rs` | Add `REASSEMBLY_BUF`, rewrite record loop, clear in cleanup |
| `src/apps/ecosystem/browser/engine/parser.rs` | Add script/style/noscript skip, `in_head` flag |
| `src/apps/ecosystem/browser/engine/render.rs` | Add table rendering, semantic blocks, display:none, lists, blockquote |
| `src/apps/ecosystem/browser/engine/types.rs` | Add `bg_color` to `TextStyle` (Tier 2.5) |
| `src/graphics/window/ecosystem/render.rs` | Draw background rects for styled text (Tier 2.5) |

---

## Testing Strategy

All changes testable with `cargo test --features std`:

| Test | Validates |
|------|-----------|
| `test_parse_strips_script` | Script tag content not in DOM |
| `test_parse_strips_style` | Style tag content not in DOM |
| `test_parse_strips_head` | Meta/link tags not in DOM |
| `test_render_table` | 3×3 table renders as rows/columns |
| `test_render_display_none` | Elements with `style="display:none"` hidden |
| `test_render_list_bullets` | `<ul><li>` renders "• " prefix |
| `test_render_ordered_list` | `<ol><li>` renders "1. " prefix |
| `test_render_blockquote` | Blockquote content indented |
| `test_render_semantic_blocks` | `<nav>`, `<section>` etc. treated as blocks |

TLS reassembly requires QEMU integration test (`make run-serial`) since it depends on the live network stack.

---

## Execution Order

```
1.1 TLS record reassembly     ← pages don't load without this
1.2 Strip script/style/noscript ← instant visual cleanup
1.3 Strip <head> content        ← more visual cleanup
1.4 Table rendering             ← high real-world impact
2.1 Semantic block elements     ← trivial, broad coverage
2.2 display:none                ← many sites depend on this
2.4 List bullets                ← visual improvement
2.3 Blockquote                  ← visual improvement
2.5 Background colors           ← polish
2.6 Select/textarea             ← form completeness
3.x Layout engine foundations   ← only after Tier 1+2 stable
```
