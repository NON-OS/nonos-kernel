# Browser Rendering Plan

## Two Issues in Current HTTPS Receive Path

### 1. TLS Record Reassembly (Critical)

The first two records decrypt fine, then **every subsequent record fails**. Root cause: `poll_receive_response` in `https.rs` does not reassemble partial TLS records across TCP reads.

TCP delivers arbitrary byte chunks. A single `tcp_poll_receive` call may contain:
- Multiple complete TLS records
- A partial record at the end (header present but payload truncated)
- Continuation bytes from a previous partial record

The current code parses each TCP chunk independently. When a chunk ends mid-record, the leftover bytes are discarded. The next TCP read starts mid-record — the code reads payload bytes as a TLS header, gets garbage content types (`0x24`, `0xDA`, `0xAB`) and absurd record lengths (`45137`, `58961`).

Once a single decrypt fails, the AEAD nonce counter (`self.seq`) still advances, permanently desyncing from the server. Every subsequent record then uses the wrong nonce and fails too.

**Evidence from logs:**
```
[HTTPS-RX] Ready len=4465 ... rec_len=1764   ← 2 records, second may be partial
[HTTPS-RX] Ready len=304  ct=0x24 rec_len=45137 ← garbage: reading mid-record
[HTTPS-RX] decrypt_app FAILED, record_len=149  ← nonce desync begins
[HTTPS-RX] decrypt_app FAILED, record_len=1343 ← every record after fails
```

**Fix:** Add a persistent `Vec<u8>` reassembly buffer that accumulates TCP data across polls. Only extract complete TLS records (5-byte header + `record_len` payload fully present) for decryption. Carry incomplete trailing bytes to the next poll.

### 2. `<script>` / `<style>` Rendered as Text

The HTML parser does not strip `<script>`, `<style>`, or `<noscript>` tags. Their text content is added to the DOM as `TextNode` children and rendered as visible page text — showing raw JavaScript and CSS.

---

## Rendering Improvements — Tiered Plan

### Tier 1 — Immediate Wins

| Fix | Effort | Impact |
|-----|--------|--------|
| **Fix TLS record reassembly** — buffer partial records across TCP reads | Medium | Sites actually load; without this nothing else matters |
| **Strip `<script>`, `<style>`, `<noscript>`** — skip to closing tag in parser | Small | Eliminates all raw JS/CSS from output |
| **Strip `<head>` content** — only render `<body>` children | Small | Removes `<meta>`, `<link>`, `<title>` text from visible output |
| **Handle `<table>/<tr>/<td>`** — render rows with tab-separated cells | Small | Most sites use tables for layout |

### Tier 2 — Basic Visual Polish

| Feature | Approach |
|---------|----------|
| **Inline `style="display:none"`** | Parse style attribute, skip node and children if display:none |
| **`<span>` passthrough** | Already works (falls through to children) |
| **Background colors for headings/code** | Add `bg_color` to `TextStyle`, render filled rect behind text |
| **`<blockquote>`** | Indent child content by extra margin |
| **Bullet points for `<li>`** | Prepend "• " for `<ul>` children, "N. " for `<ol>` |

### Tier 3 — Layout Engine

| Feature | Description |
|---------|-------------|
| **Block vs inline model** | Track whether elements are block (new line) or inline (flow) |
| **CSS class-based hiding** | Parse `<style>` blocks for `.foo { display: none }`, apply to matching nodes |
| **Basic `<img>` rendering** | Fetch image URLs, decode dimensions, render placeholder with alt text |
| **Flexbox/grid** | Probably not worth the complexity |

### Tier 4 — Out of Scope

- JavaScript execution (no JS engine)
- CSS cascade / specificity
- Web fonts
- Shadow DOM, Web Components
- Canvas, WebGL

---

## Recommended Execution Order

1. **Fix TLS record reassembly** — highest priority, pages don't load without it
2. **Strip `<script>/<style>/<noscript>/<head>`** — instant visual cleanup
3. **Add `<table>` rendering** — high real-world impact
4. **Handle `display:none`** — many sites hide content with inline styles

## Current Renderer Capabilities

**Parsed and rendered:**
- `<b>`, `<strong>` → bold
- `<i>`, `<em>` → italic
- `<u>` → underline
- `<h1>`–`<h6>` → headings with bold + level
- `<code>`, `<pre>` → monospace
- `<a>` → clickable links
- `<img>` → image placeholder with alt text
- `<input>` → form input box
- `<button>` → button
- `<p>`, `<div>`, `<li>` → block-level newlines
- `<ul>`, `<ol>` → block-level newlines
- `<br>`, `<hr>` → line break / horizontal rule

**Not handled (renders inner text):**
- `<script>`, `<style>`, `<noscript>`
- `<table>`, `<thead>`, `<tbody>`, `<td>`, `<th>`
- `<nav>`, `<header>`, `<footer>`, `<section>`, `<article>`, `<aside>`
- `<select>`, `<option>`, `<textarea>`
- `<iframe>`, `<video>`, `<audio>`, `<canvas>`, `<svg>`
