#!/usr/bin/env python3
"""Package a gateway binary and smoke-test the extracted archive."""

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

binary, version, platform = sys.argv[1:]
name = f"oauth2-mcp-gateway-{version}-{platform}"
dist = Path("dist").resolve()
dist.mkdir(exist_ok=True)

with tempfile.TemporaryDirectory(prefix="gateway-release-") as work:
    root = Path(work)
    package = root / name
    package.mkdir()
    for source in (binary, "LICENSE", "README.md"):
        shutil.copy2(source, package)

    archive = shutil.make_archive(
        str(dist / name),
        "zip" if platform.startswith("windows-") else "gztar",
        root_dir=root,
        base_dir=name,
    )
    extracted = root / "extracted"
    shutil.unpack_archive(archive, extracted)
    exe = extracted / name / Path(binary).name
    actual = subprocess.check_output([exe, "--version"], text=True, timeout=30).strip()
    expected = f"oauth2-mcp-gateway {version}"
    if actual != expected:
        raise SystemExit(f"expected {expected!r}, got {actual!r}")

    config = extracted / "gateway.json"
    config.write_text(
        json.dumps(
            {
                "listen": "127.0.0.1:8080",
                "public_url": "http://127.0.0.1:8080",
                "state_path": str(extracted / "state.json"),
                "oauth": {"owner_password": "release-smoke-test-only"},
                "upstream": {"transport": "http", "url": "http://127.0.0.1:9000/mcp"},
            }
        ),
        encoding="utf-8",
    )
    subprocess.run([exe, "check", "--config", config], check=True, timeout=30)
