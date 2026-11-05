"""List the installed Python distributions with version and license, e.g. for THIRD_PARTY_LICENSES.txt.

Run it where requirements.txt is installed (a virtual environment or the container):
    python scripts/third_party_licenses.py            # one line per package: name==version<TAB>license
    python scripts/third_party_licenses.py --texts    # additionally the license files shipped with each package
"""
from __future__ import annotations

import sys
from importlib import metadata

_LICENSE_NAMES = ("LICENSE", "LICENCE", "COPYING", "NOTICE")


def license_of(dist: metadata.Distribution) -> str:
    md = dist.metadata
    expression = md.get("License-Expression")
    if expression:
        return expression
    classifiers = [c.split(" :: ")[-1] for c in (md.get_all("Classifier") or []) if c.startswith("License ::")]
    if classifiers:
        return " / ".join(classifiers)
    text = (md.get("License") or "").strip().splitlines()
    return text[0][:80] if text else "unknown"


def license_texts(dist: metadata.Distribution) -> list[tuple[str, str]]:
    declared = dist.metadata.get_all("License-File") or []
    texts = []
    for file in dist.files or []:
        name = str(file)
        base = name.rsplit("/", 1)[-1].upper()
        if ".dist-info/" in name and (base.startswith(_LICENSE_NAMES) or any(name.endswith(d) for d in declared)):
            try:
                texts.append((name, file.read_text(encoding="utf-8")))
            except (OSError, UnicodeDecodeError):
                continue
    return texts


def main(argv: list[str]) -> int:
    unique = {}
    for dist in metadata.distributions():
        name = dist.metadata.get("Name")
        if name:
            unique.setdefault(name.lower(), dist)
    dists = [unique[k] for k in sorted(unique)]
    for dist in dists:
        print(f"{dist.metadata['Name']}=={dist.version}\t{license_of(dist)}")
    if "--texts" in argv:
        for dist in dists:
            for name, text in license_texts(dist):
                print("\n" + "=" * 78 + f"\n{dist.metadata['Name']} {dist.version}: {name}\n" + "=" * 78)
                print(text.rstrip())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
