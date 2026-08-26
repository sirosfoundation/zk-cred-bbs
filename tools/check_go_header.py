#!/usr/bin/env python3
"""Fail if include/zk_cred_bbs_go.h has drifted from src/go_ffi.rs.

The Rust side already asserts every ABI constant at compile time, but those
assertions only catch a change made in Rust — they cannot see the C header.
This closes the other direction: it re-derives the constants and the exported
function names from both files and compares.

Adapted from the guard zk-cred-vega uses for its own hand-written header;
zk-cred-longfellow's header has no equivalent check today, which is why its
own comment has to ask a human to keep it in sync by hand.
"""

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUST = ROOT / "src" / "go_ffi.rs"
HEADER = ROOT / "include" / "zk_cred_bbs_go.h"

# `pub const ZK_CRED_BBS_OK: i32 = 0;`
RUST_CONST = re.compile(
    r"^pub const (ZK_CRED_BBS_\w+):\s*\w+\s*=\s*(-?\d+)", re.MULTILINE
)
# `#define ZK_CRED_BBS_OK 0` / `(-1)` / `1u`
HEADER_CONST = re.compile(
    r"^#define (ZK_CRED_BBS_\w+)\s+\(?(-?\d+)u?\)?\s*$", re.MULTILINE
)
RUST_FN = re.compile(r"pub unsafe extern \"C\" fn (zk_cred_bbs_\w+)")
HEADER_FN = re.compile(r"^(?:int32_t|void)\s+(zk_cred_bbs_\w+)\(", re.MULTILINE)


def main() -> int:
    rust = RUST.read_text()
    header = HEADER.read_text()

    problems = []

    rust_consts = {name: int(val) for name, val in RUST_CONST.findall(rust)}
    header_consts = {name: int(val) for name, val in HEADER_CONST.findall(header)}
    if not rust_consts:
        problems.append(f"no constants found in {RUST} — has the declaration style changed?")
    if not header_consts:
        problems.append(f"no #defines found in {HEADER} — has the style changed?")

    for name in sorted(set(rust_consts) | set(header_consts)):
        in_rust = rust_consts.get(name)
        in_header = header_consts.get(name)
        if in_rust is None:
            problems.append(f"{name} is #defined in the header but absent from go_ffi.rs")
        elif in_header is None:
            problems.append(f"{name} is declared in go_ffi.rs but absent from the header")
        elif in_rust != in_header:
            problems.append(f"{name}: go_ffi.rs says {in_rust}, header says {in_header}")

    rust_fns = set(RUST_FN.findall(rust))
    header_fns = set(HEADER_FN.findall(header))
    for name in sorted(rust_fns - header_fns):
        problems.append(f"{name} is exported from Rust but not declared in the header")
    for name in sorted(header_fns - rust_fns):
        problems.append(f"{name} is declared in the header but not exported from Rust")

    if problems:
        print("C header has drifted from src/go_ffi.rs:", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        return 1

    print(
        f"C header matches src/go_ffi.rs "
        f"({len(rust_consts)} constants, {len(rust_fns)} functions)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
