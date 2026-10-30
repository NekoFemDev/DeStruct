#!/usr/bin/env python3
"""Build the vendored per-version opcode data for internal/hermes/opcodes.

Data source
-----------
The instruction names, opcode numbers and operand layouts are taken from
the per-version ``data/opcode.json`` tables of github.com/Kirlif/HBC-Tool
(Apache-2.0), whose fork added support for bytecode versions 83 through 99.
That project's JSON stores instructions as an ordered object; the position
of an instruction in the object is its opcode number, and an operand type
suffixed with ``:S`` denotes a string table index.

Operand *meanings* that the JSON cannot express (function_id, bigint_id)
and the RET-target flag are applied from static tables derived from the
Hermes authority itself (facebook/hermes, MIT): the OPERAND_FUNCTION_ID /
OPERAND_BIGINT_ID / DEFINE_RET_TARGET annotations in
include/hermes/BCGen/HBC/BytecodeList.def. A small corrections table fixes
data errors that were verified directly against the Hermes source at the
matching bytecode-version commits (see CORRECTIONS).

deliberately not sourced from hermes-dec, whose generated tables would
otherwise be useful: that project is AGPL-3.0 and its data must not be
vendored into this repository.

Usage
-----
    python3 build_data.py [--hbctool-dir PATH] [--out-dir PATH]

Run from anywhere; defaults are resolved relative to this script (the
hbctool checkout is expected at <repo>/hbctool/hbctool/hbc, matching the
repository layout).
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parent.parent.parent.parent  # internal/hermes/opcodes/data -> repo root

SOURCE = "github.com/Kirlif/HBC-Tool (Apache-2.0)"

# --- Meanings -----------------------------------------------------------------
#
# OPERAND_FUNCTION_ID(name, operandNumber) annotations from Hermes's
# BytecodeList.def, mapped to zero-based operand indices. The set of names
# is stable across the versions that contain them.
FUNCTION_ID_OPERANDS = {
    "CallDirect": 2,
    "CallDirectLongIndex": 2,
    "CreateClosure": 2,
    "CreateClosureLongIndex": 2,
    "CreateGenerator": 2,
    "CreateGeneratorLongIndex": 2,
    "CreateGeneratorClosure": 2,
    "CreateGeneratorClosureLongIndex": 2,
    "CreateAsyncClosure": 2,
    "CreateAsyncClosureLongIndex": 2,
}

# OPERAND_BIGINT_ID annotations.
BIGINT_ID_OPERANDS = {
    "LoadConstBigInt": 1,
    "LoadConstBigIntLongIndex": 1,
}

# DEFINE_RET_TARGET names, unioned across the versions that use them.
RET_TARGETS = {
    "Call",
    "Call1",
    "Call2",
    "Call3",
    "Call4",
    "CallLong",
    "Construct",
    "ConstructLong",
    "CallDirect",
    "CallDirectLongIndex",
    "CallRequire",
    "CallWithNewTarget",
    "CallWithNewTargetLong",
}

# --- Corrections ---------------------------------------------------------------
#
# {version: {instruction_name: {"operands": [...]}}}
# Operand strings use the same "Type" / "Type:meaning" notation as the input
# JSON. Everything else about the instruction is kept.
CORRECTIONS = {
    # The hbctool v99 table lists NewFastArray as (Reg8, Reg8, UInt16); the
    # Hermes source at both bytecode-version-99 commits (42235b8d91 and
    # 913d31acd1, "Bump bytecode version to 99") declares
    # DEFINE_OPCODE_2(NewFastArray, Reg8, UInt16). Take the source.
    99: {
        "NewFastArray": {"operands": ["Reg8", "UInt16"]},
    },
}

MEANING_NAMES = {
    "S": "string_id",
    "function_id": "function_id",
    "bigint_id": "bigint_id",
}


def parse_operand(raw: str) -> dict:
    """Parse one "Type" / "Type:S" operand string into a data dict."""
    operand_type, _, suffix = raw.partition(":")
    out = {"type": operand_type.strip()}
    if suffix.strip() == "S":
        out["meaning"] = "string_id"
    elif suffix.strip():
        raise SystemExit(f"unknown operand suffix {suffix!r} in {raw!r}")
    return out


def build_version(version: int, opcode_json: pathlib.Path, builtins: dict) -> dict:
    raw = json.loads(opcode_json.read_text())
    if not isinstance(raw, dict):
        raise SystemExit(f"{opcode_json}: expected an ordered object")

    instructions = []
    for opcode, (name, operands) in enumerate(raw.items()):
        entry: dict = {"name": name, "opcode": opcode}
        op_list = [parse_operand(o) for o in operands]

        for idx, operand in enumerate(op_list):
            if idx == FUNCTION_ID_OPERANDS.get(name):
                operand["meaning"] = "function_id"
            elif idx == BIGINT_ID_OPERANDS.get(name):
                operand["meaning"] = "bigint_id"

        if op_list:
            entry["operands"] = op_list
        if name in RET_TARGETS:
            entry["retTarget"] = True

        correction = CORRECTIONS.get(version, {}).get(name)
        if correction:
            if "operands" in correction:
                entry["operands"] = [parse_operand(o) for o in correction["operands"]]
            entry["corrected"] = True

        instructions.append(entry)

    data = {
        "version": version,
        "source": SOURCE,
        "instructions": instructions,
    }

    entry = builtins.get(version)
    if entry:
        data["builtins"] = entry["names"]
        data["builtinsApproximate"] = bool(entry.get("approximate"))
        data["builtinsSource"] = entry.get("source", "")

    return data


def load_builtins(path: pathlib.Path) -> dict:
    """Load data/builtins.json (built by build_builtins.py), keyed by version."""
    if not path.is_file():
        return {}
    doc = json.loads(path.read_text())
    return {int(v): entry for v, entry in doc.get("versions", {}).items()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--hbctool-dir",
        type=pathlib.Path,
        default=REPO / "hbctool" / "hbctool" / "hbc",
        help="directory containing hbcNN/data/opcode.json",
    )
    parser.add_argument(
        "--out-dir",
        type=pathlib.Path,
        default=HERE,
        help="directory to write hbcNN.json into",
    )
    parser.add_argument(
        "--builtins",
        type=pathlib.Path,
        default=HERE / "builtins.json",
        help="builtins.json produced by build_builtins.py (optional)",
    )
    args = parser.parse_args()

    if not args.hbctool_dir.is_dir():
        print(f"hbctool data directory not found: {args.hbctool_dir}", file=sys.stderr)
        return 1

    args.out_dir.mkdir(parents=True, exist_ok=True)
    builtins = load_builtins(args.builtins)

    version_dirs = sorted(
        (
            int(m.group(1)),
            d / "data" / "opcode.json",
        )
        for d in args.hbctool_dir.iterdir()
        if (m := re.fullmatch(r"hbc(\d+)", d.name)) and (d / "data" / "opcode.json").is_file()
    )
    if not version_dirs:
        print(f"no hbcNN/data/opcode.json found under {args.hbctool_dir}", file=sys.stderr)
        return 1

    for version, opcode_json in version_dirs:
        if not 59 <= version <= 99:
            continue
        data = build_version(version, opcode_json, builtins)
        out = args.out_dir / f"hbc{version}.json"
        out.write_text(json.dumps(data, indent=2) + "\n")
        print(f"hbc{version}.json: {len(data['instructions'])} instructions")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
