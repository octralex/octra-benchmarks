#!/usr/bin/env python3
import hashlib
import json
from pathlib import Path
import tarfile
import urllib.request

BASE = Path(__file__).resolve().parent
VERSION = "23.1.5"
EXPECTED_SHA256 = "166d601c6e9629e404ac0301b498bdb02e418619e1697c6e98efe9c9a6f18f0c"


def main():
    metadata = BASE / "libomp-bottle.json"
    if not metadata.exists():
        with urllib.request.urlopen("https://formulae.brew.sh/api/formula/libomp.json") as response:
            metadata.write_bytes(response.read())
    document = json.loads(metadata.read_text())
    if document["versions"]["stable"] != VERSION:
        raise RuntimeError("libomp metadata differs from the reviewed version")
    bottle = document["bottle"]["stable"]["files"]["arm64_tahoe"]
    if bottle["sha256"] != EXPECTED_SHA256:
        raise RuntimeError("libomp bottle differs from the reviewed hash")
    archive = BASE / "libomp-bottle.tar.gz"
    if not archive.exists():
        request = urllib.request.Request(bottle["url"], headers={"Authorization": "Bearer QQ=="})
        with urllib.request.urlopen(request) as response:
            archive.write_bytes(response.read())
    if hashlib.sha256(archive.read_bytes()).hexdigest() != EXPECTED_SHA256:
        raise RuntimeError("libomp archive hash mismatch")
    target = BASE / "third-party/libomp"
    target.mkdir(parents=True, exist_ok=True)
    with tarfile.open(archive) as source:
        for member in source.getmembers():
            path = Path(member.name)
            if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] != "libomp":
                raise RuntimeError("unsafe libomp archive member")
        source.extractall(target)
    runtime = target / "libomp" / VERSION / "lib/libomp.dylib"
    if not runtime.is_file():
        raise RuntimeError("libomp runtime missing")
    print(json.dumps({"version": VERSION, "sha256": EXPECTED_SHA256, "runtime": str(runtime)}, indent=2))


if __name__ == "__main__":
    main()
