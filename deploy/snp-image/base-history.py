#!/usr/bin/env python3
"""Read public base signatures and record bases after successful reconstruction."""

import base64
import json
import re
import sys
from pathlib import Path


def validate(entry):
    cloud = entry.get("cloud")
    if cloud not in ("gcp", "aws"):
        raise ValueError("base cloud must be gcp or aws")
    for field, pattern in (
        ("sourceCommit", r"[0-9a-f]{40}"),
        ("base_uki_sha256", r"[0-9a-f]{64}"),
        ("base", r"snp-base:[0-9a-f]{%d}" % (64 if cloud == "gcp" else 96)),
    ):
        value = entry.get(field)
        if not isinstance(value, str) or not re.fullmatch(pattern, value):
            raise ValueError(f"invalid or missing {field} for {cloud} base")
    cmdline = entry.get("kernelCmdline")
    if not isinstance(cmdline, str) or not cmdline or any(c in cmdline for c in "\x00\r\n"):
        raise ValueError(f"invalid or missing kernelCmdline for {cloud} base")
    encoded = entry.get("base_uki_signature")
    if not isinstance(encoded, str) or not encoded or len(encoded) > 128 * 1024:
        raise ValueError(f"invalid or missing base_uki_signature for {cloud} base")
    signature = base64.b64decode(encoded, validate=True)
    if base64.b64encode(signature).decode("ascii") != encoded:
        raise ValueError(f"noncanonical base_uki_signature for {cloud} base")
    return signature


def select(history, cloud=None, digest=None):
    if digest is not None:
        if not re.fullmatch(r'snp-base:(?:[0-9a-f]{64}|[0-9a-f]{96})', digest):
            raise ValueError(f"invalid SNP base selector: {digest}")
        matches = [b for b in history.get("base_images", [])
                   if b.get("base") == digest and (cloud is None or b.get("cloud") == cloud)]
        if len(matches) != 1:
            raise ValueError(f"expected one recorded SNP base for {digest}, found {len(matches)}")
        return matches[0]
    entry = next((b for b in reversed(history.get("base_images", [])) if b.get("cloud") == cloud), None)
    if entry is None:
        raise ValueError(f"no recorded base for {cloud}")
    return entry


def main():
    action, history_name, cloud, directory, *digests = sys.argv[1:]
    if len(digests) > 1 or (digests and action != "extract"):
        raise ValueError("only extract accepts an optional base digest")
    history_path = Path(history_name)
    history = json.loads(history_path.read_text())
    directory = Path(directory)
    if action == "extract":
        entry = select(history, cloud, digests[0] if digests else None)
        signature = validate(entry)
        for field, filename in (("sourceCommit", "commit"), ("kernelCmdline", "cmdline"),
                                ("base_uki_sha256", "expected-sha256"), ("base", "expected-pcr")):
            (directory / filename).write_text(entry[field])
        (directory / "base-signature.pk7").write_bytes(signature)
    elif action == "record":
        # The shell caller has verified the detached signature, the PCR value,
        # and byte-for-byte equality with the supplied signed release image.
        entry = dict(cloud=cloud, base=(directory / "actual-pcr").read_text().strip(),
                     base_uki_sha256=(directory / "actual-sha256").read_text().strip(),
                     sourceCommit=(directory / "commit").read_text().strip(),
                     kernelCmdline=(directory / "cmdline").read_text(),
                     base_uki_signature=base64.b64encode((directory / "base-signature.pk7").read_bytes()).decode("ascii"))
        validate(entry)
        bases = history.setdefault("base_images", [])
        if entry not in bases:
            bases.append(entry)
        # Refuse to overwrite edits made while the reconstruction was running.
        if history_path.read_bytes() != (directory / "original-history.json").read_bytes():
            raise ValueError("image history changed during reconstruction; retry recording")
        updated = history_path.with_name(history_path.name + ".tmp")
        updated.write_text(json.dumps(history, indent=2) + "\n")
        updated.replace(history_path)
    else:
        raise ValueError(f"unknown action: {action}")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, TypeError, OSError) as error:
        sys.exit(f"ERROR: {error}")
