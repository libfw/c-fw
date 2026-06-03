# c-fw config grammars

c-fw loads ACL rulesets from two interchangeable front-ends:

- **HCL** — the declarative HCL subset, parsed by the vendored
  [libhcl/c-hcl](https://github.com/libhcl/c-hcl) (see its
  [GRAMMAR.md](https://github.com/libhcl/c-hcl/blob/main/GRAMMAR.md)); the
  HCL-to-ACL mapping lives in `acl_hcl.c`.
- **JSON** — a small built-in JSON parser (`json.c`) used by `acl.c` to load
  rulesets that were emitted by tooling.

This document specifies the **JSON parser** (`json.c`/`json.h`), derived
directly from the hand-written recursive-descent parser. When the code changes,
change this too.

The HCL grammar is *not* repeated here — it is owned and versioned by c-hcl.

---

## 1. Grammar (EBNF)

The parser is a classic recursive-descent JSON reader (`jparse_value` dispatches
on the first non-space byte). Whitespace (`isspace`) is skipped between tokens.

```ebnf
document = value ;            (* see §3: trailing bytes are NOT rejected *)

value    = object | array | string | number | "true" | "false" | "null" ;

object   = "{" [ member { "," member } ] "}" ;
member   = string ":" value ;

array    = "[" [ value { "," value } ] "]" ;

string   = '"' { char | escape } '"' ;
escape   = "\\\"" | "\\\\" | "\\/" | "\\b" | "\\f" | "\\n" | "\\r" | "\\t"
         | "\\u" hex hex hex hex ;

number   = (* whatever strtod() accepts -- see §3 *) ;
```

The value model is one `jnode` per value (`jtype`:
`J_NULL`/`J_BOOL`/`J_NUM`/`J_STR`/`J_ARR`/`J_OBJ`). Objects keep parallel
`keys[]`/`vals[]` arrays; arrays keep `vals[]` only.

### Top level

Any JSON value is a valid document — `json_parse` does not require the root to
be an object or array (consistent with RFC 8259).

---

## 2. Strings & escapes

- Standard JSON escapes are decoded: `\" \\ \/ \b \f \n \r \t`.
- `\uXXXX` is decoded from 4 hex digits and **UTF-8 encoded** (1–3 bytes) via
  `jutf8_encode`.
- Any other `\x` (or a truncated `\u`) is a parse error.
- The decoded buffer is sized to the encoded length (decoding never grows a
  string), so it is allocated once up front.

---

## 3. Deliberate deviations from strict RFC 8259

This parser is intentionally minimal — it reads tool-generated rulesets, not
arbitrary hostile JSON. Known, intentional relaxations:

1. **No trailing-content check.** `json_parse` parses exactly one top-level
   `value` and returns it; any bytes *after* that value are ignored rather than
   rejected. (Strict JSON requires the value to be the entire input.)
2. **Numbers are whatever `strtod` accepts.** This is a superset of JSON
   numbers: it also accepts a leading `+`, `inf`/`nan`, hex floats (`0x1.8p3`),
   and leading whitespace. JSON's own grammar (no leading `+`, no leading
   zeros-then-digit rule) is therefore *not* enforced. The match is bounded to
   the input (`endp > end` is rejected), so it will not read past the buffer,
   **but the buffer is assumed NUL-terminated** (as produced by the file loader
   in `acl.c`).
3. **`\uXXXX` surrogate pairs are not combined.** Each `\u` escape is encoded
   independently, so a UTF-16 surrogate pair (`😀`) is emitted as two
   separate 3-byte sequences rather than one 4-byte code point. BMP code points
   are correct.
4. **Duplicate object keys are kept.** All members are stored; `jget` returns
   the **first** match for a key.

If you need a strict, conformance-tested JSON reader, this is not it — it is a
loader for trusted ruleset files.

---

## 4. Public API (`json.h`)

| Function       | Purpose                                            |
|----------------|----------------------------------------------------|
| `json_parse`   | Parse `(src, len)` into a `jnode*`; NULL on error. |
| `jfree`        | Recursively free a `jnode` tree.                   |
| `jget`         | First value for `key` in an object node, else NULL.|

---

## 5. Parsing strategy (why hand-written)

Like the rest of the libhcl/libfw family, this is hand-written C — **no
flex/bison**, no build-time codegen. JSON's grammar is small and fully
recursive-descent-friendly (no operator precedence), so a generator would add a
build dependency and untestable table code for no benefit. The whole parser is
~300 lines, dependency-free (`cc json.c`), and 100 %-instrumentable, including
its out-of-memory paths via the `cfw_alloc.h` allocation-budget hook
(`acl_alloc_budget`, shared with `acl.c`).
