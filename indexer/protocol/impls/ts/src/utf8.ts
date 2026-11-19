// Strict RFC-3629 UTF-8 validator (protocol-spec.md §1, §5; SPEC-conformance.md §9 `sm_valid_utf8`).
// Reject overlong encodings, lone surrogates U+D800..U+DFFF, and code points > U+10FFFF. This is a
// WHOLE-payload test (§1): a payload that starts valid but contains an invalid sequence later is
// NOT a post. Returns true iff every byte is part of a strictly-valid sequence.
import type { Bytes } from "./bytes.ts";

export function validUtf8(b: Bytes): boolean {
  let i = 0;
  const n = b.length;
  while (i < n) {
    const c = b[i];
    if (c < 0x80) {
      i += 1;
      continue;
    }
    let len: number;
    let cp: number;
    let lo: number; // minimum code point for this length (overlong guard)
    if ((c & 0xe0) === 0xc0) {
      len = 2; cp = c & 0x1f; lo = 0x80;
    } else if ((c & 0xf0) === 0xe0) {
      len = 3; cp = c & 0x0f; lo = 0x800;
    } else if ((c & 0xf8) === 0xf0) {
      len = 4; cp = c & 0x07; lo = 0x10000;
    } else {
      return false; // 0x80..0xBF continuation as lead, or 0xF8..0xFF (incl. 0xFF) — invalid
    }
    if (i + len > n) return false; // truncated multibyte at end
    for (let k = 1; k < len; k++) {
      const cc = b[i + k];
      if ((cc & 0xc0) !== 0x80) return false; // not a continuation byte
      cp = (cp << 6) | (cc & 0x3f);
    }
    if (cp < lo) return false; // overlong
    if (cp > 0x10ffff) return false; // out of Unicode range
    if (cp >= 0xd800 && cp <= 0xdfff) return false; // lone surrogate
    i += len;
  }
  return true;
}
