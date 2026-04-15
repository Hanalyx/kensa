#!/usr/bin/env python3
"""
Add Ubuntu `when: apt` implementations to corpus rules that use
package_present or package_absent as their remediation mechanism.

For each implementation block that uses package_present/package_absent,
this script prepends a matching `when: apt` block using apt_present/apt_absent.
Rules that already have a `when: apt` block are skipped.

Usage:
    python3 scripts/add_ubuntu_pkg_impls.py /path/to/rules/dir

The script modifies files in-place. Run TestCorpusParity afterwards to verify.
"""

import sys
import os
import yaml

RHEL_TO_APT = {
    "package_present": "apt_present",
    "package_absent": "apt_absent",
}


def build_apt_impl(mechanism: str, pkg_name: str, state: str) -> dict:
    """Build the Ubuntu when:apt implementation dict."""
    return {
        "when": "apt",
        "check": {
            "method": "package_state",
            "name": pkg_name,
            "state": state,
        },
        "remediation": {
            "mechanism": RHEL_TO_APT[mechanism],
            "name": pkg_name,
        },
    }


def already_has_apt(impls: list) -> bool:
    """Return True if any implementation already gates on 'apt'."""
    for impl in impls:
        w = impl.get("when")
        if w == "apt":
            return True
        if isinstance(w, dict):
            # all: [apt] or any: [apt, ...]
            for val in w.values():
                if isinstance(val, list) and "apt" in val:
                    return True
    return False


def process_file(path: str) -> bool:
    """
    Add Ubuntu implementations to path if needed.
    Returns True if the file was modified.
    """
    with open(path) as f:
        raw = f.read()

    try:
        doc = yaml.safe_load(raw)
    except yaml.YAMLError as e:
        print(f"  SKIP (parse error): {path}: {e}", file=sys.stderr)
        return False

    if not isinstance(doc, dict):
        return False

    impls = doc.get("implementations", [])
    if not impls:
        return False

    if already_has_apt(impls):
        return False  # already patched

    # Find all implementations that use package_present/absent
    # and collect the (index, mechanism, name, state) tuples.
    patches = []
    for i, impl in enumerate(impls):
        rem = impl.get("remediation", {})
        if not isinstance(rem, dict):
            continue
        mech = rem.get("mechanism", "")
        if mech not in RHEL_TO_APT:
            continue
        # Get the package name from the remediation or check block.
        name = rem.get("name") or impl.get("check", {}).get("name", "")
        if not name:
            continue
        state = "present" if mech == "package_present" else "absent"
        patches.append((i, mech, str(name), state))

    if not patches:
        return False

    # Build the new implementations list: insert a `when: apt` block
    # immediately before each patched implementation. Process in reverse
    # index order so earlier insertions don't shift later indices.
    new_impls = list(impls)
    for insert_at, mech, name, state in reversed(patches):
        apt_impl = build_apt_impl(mech, name, state)
        new_impls.insert(insert_at, apt_impl)

    doc["implementations"] = new_impls

    # Write back with pyyaml. Use default_flow_style=False for block style
    # and allow_unicode=True to preserve any non-ASCII content.
    new_raw = yaml.dump(
        doc,
        default_flow_style=False,
        allow_unicode=True,
        sort_keys=False,
        width=120,
    )

    with open(path, "w") as f:
        f.write(new_raw)

    return True


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <rules-dir>", file=sys.stderr)
        sys.exit(1)

    rules_dir = sys.argv[1]
    modified = 0
    skipped = 0
    total = 0

    for root, _, files in os.walk(rules_dir):
        for fname in sorted(files):
            if not fname.endswith(".yml"):
                continue
            total += 1
            path = os.path.join(root, fname)
            if process_file(path):
                modified += 1
                print(f"  patched: {os.path.relpath(path, rules_dir)}")
            else:
                skipped += 1

    print(f"\n{total} files scanned, {modified} patched, {skipped} skipped")


if __name__ == "__main__":
    main()
