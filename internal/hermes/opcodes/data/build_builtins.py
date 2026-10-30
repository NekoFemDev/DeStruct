#!/usr/bin/env python3
"""Build data/builtins.json: per-bytecode-version builtin function name lists.

These lists render the `# Built-in function: [#N name]` comments; index N
is the builtin callable id space that CallBuiltin / GetBuiltinClosure
operands select, so both names and order matter.

Source: the Hermes engine's own include/hermes/FrontEndDefs/Builtins.def
(facebook/hermes, MIT License) - and, for bytecode versions before that
file existed, its predecessor include/hermes/Inst/Builtins.def. SOURCES
below pins one Hermes commit per bytecode version: the last commit whose
tree carries the list in effect for that version. The mapping was derived
from the history of Builtins.def cross-checked against the bytecode
version of each commit, and validated against the reference hermes-dec
disassembler's generated lists for every version hermes-dec ships
(see the validation notes per entry).

Versions marked `approximate` could not be pinned to a hermes-dec-matching
or fork-verifiable list: the bytecode format version was reused across
divergent lineages (mainline vs the React Native fork), so more than one
list existed for the same version number. Those entries carry the closest
same-lineage list and are safe for rendering (only comments differ from a
truly matching build's output).

Usage: python3 build_builtins.py [--out builtins.json]
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import urllib.request

HERE = pathlib.Path(__file__).resolve().parent
RAW = "https://raw.githubusercontent.com/facebook/hermes/{sha}/{path}"

FRONTEND = "include/hermes/FrontEndDefs/Builtins.def"
INST = "include/hermes/Inst/Builtins.def"

# version -> (source path, commit prefix, approximate, note)
SOURCES: dict[int, tuple[str, str, bool, str]] = {
    59: (INST, "f22a18f67d", False, "validated against hermes-dec hbc59"),
    61: (INST, "f22a18f67d", False, "same list as v59 (validated against hermes-dec hbc61)"),
    62: (INST, "ae0bc93f49", False, "validated against hermes-dec hbc62"),
    74: (FRONTEND, "d1637f28eb", False, "validated against the hermes v0.4.0 tag (bytecode 74)"),
    76: (FRONTEND, "df60b4768a", False, "validated against hermes-dec hbc76 and tag v0.7.0"),
    83: (FRONTEND, "c2cd9e385a", False, "validated against hermes-dec hbc83 and tag v0.8.0"),
    84: (FRONTEND, "c2cd9e385a", False, "same list as v83; validated against tag v0.8.1"),
    85: (FRONTEND, "c2cd9e385a", False, "validated against hermes-dec hbc85"),
    86: (FRONTEND, "b8235156c0", False, "validated against hermes-dec hbc86"),
    87: (FRONTEND, "b8235156c0", False, "validated against hermes-dec hbc87"),
    88: (FRONTEND, "b8235156c0", True, "inherited (no list change between v86 and v89 on mainline); hermes-dec ships no v88"),
    89: (FRONTEND, "498f7cb64a", False, "validated against hermes-dec hbc89 and tag v0.12.0"),
    90: (FRONTEND, "906b5cff32", False, "validated against hermes-dec hbc90 (initial v90 state)"),
    91: (FRONTEND, "906b5cff32", True, "hermes-dec resolves v91 through its hbc90 table; fork list unverified"),
    92: (FRONTEND, "fef025ee44", True, "fork-modified list (hermes-dec hbc92 does not match any mainline state)"),
    93: (FRONTEND, "906b5cff32", True, "hermes-dec resolves v93 through its hbc90 table; fork list unverified"),
    94: (FRONTEND, "fef025ee44", True, "hermes-dec resolves v94 through its hbc92 table; closest same-lineage state"),
    95: (FRONTEND, "v0.13.0", False, "tag v0.13.0; identical to hermes-dec hbc95/hbc96"),
    96: (FRONTEND, "v0.13.0", False, "tag v0.13.0; identical to hermes-dec hbc96"),
    97: (FRONTEND, "fef025ee44", False, "validated against hermes-dec hbc97 (late v90 state carried into v97)"),
    98: (FRONTEND, "0a6126fbd5", False, "validated against hermes-dec hbc98 (final v98 state)"),
    99: (FRONTEND, "hermes-v260318099.0.4", False, "newest v99 tag state; hermes-dec hbc99 is stale (pre-setFunctionName)"),
}

ALL_VERSIONS = sorted(SOURCES)


def fetch(sha: str, path: str) -> str:
    url = RAW.format(sha=sha, path=path)
    with urllib.request.urlopen(url) as resp:
        return resp.read().decode()


def parse_builtins(text: str) -> list[str]:
    names: list[str] = []
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("//"):
            continue
        m = re.match(r"(?:BUILTIN_METHOD|NORMAL_METHOD|FROZEN_METHOD)\((\w+),\s*(\w+)\)", s)
        if m:
            names.append(f"{m.group(1)}.{m.group(2)}")
            continue
        m = re.match(r"PRIVATE_BUILTIN\((\w+)\)", s)
        if m:
            names.append(m.group(1))
            continue
        m = re.match(r"JS_BUILTIN\((\w+)\)", s)
        if m:
            names.append(m.group(1))
            continue
    return names


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=pathlib.Path, default=HERE / "builtins.json")
    args = ap.parse_args()

    versions: dict[str, dict] = {}
    for version in ALL_VERSIONS:
        path, sha, approximate, note = SOURCES[version]
        text = fetch(sha, path)
        names = parse_builtins(text)
        if not names:
            raise SystemExit(f"v{version}: no builtin names parsed from {sha}:{path}")
        versions[str(version)] = {
            "names": names,
            "source": f"facebook/hermes {sha} ({path})",
            "approximate": approximate,
            "note": note,
        }
        print(f"v{version}: {len(names)} builtins ({sha}{' approx' if approximate else ''})")

    doc = {
        "source": (
            "facebook/hermes Builtins.def (MIT License) at the commit pinned per version; "
            "validated against the reference hermes-dec generated lists where available"
        ),
        "versions": versions,
    }
    args.out.write_text(json.dumps(doc, indent=2) + "\n")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
