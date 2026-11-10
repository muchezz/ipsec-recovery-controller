"""Build twice from the same source and refuse non-reproducible release artifacts.

Run with Python 3.12 and requirements-build.txt installed. Output is under dist/.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from email.parser import Parser
from importlib.metadata import version
from pathlib import Path
from zipfile import ZipFile

ROOT = Path(__file__).resolve().parents[1]


def run(*args: str) -> str:
    return subprocess.check_output(args, cwd=ROOT, text=True).strip()


def main() -> None:
    commit = run("git", "rev-parse", "HEAD")
    epoch = run("git", "show", "-s", "--format=%ct", "HEAD")
    environment = dict(os.environ, SOURCE_DATE_EPOCH=epoch, PYTHONHASHSEED="0")
    artifact_sets = []
    for suffix in ("first", "second"):
        output = ROOT / "dist" / "release" / suffix
        output.mkdir(parents=True, exist_ok=True)
        if any(output.iterdir()):
            raise RuntimeError(f"refusing nonempty build directory: {output}")
        subprocess.run([sys.executable, "-m", "build", "--no-isolation", "--outdir", str(output)],
                       cwd=ROOT, env=environment, check=True)
        artifacts = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                     for path in output.iterdir() if path.is_file()}
        if len(artifacts) != 2:
            raise RuntimeError("expected exactly one wheel and one source distribution")
        artifact_sets.append(artifacts)
    if artifact_sets[0] != artifact_sets[1]:
        raise RuntimeError("release builds are not byte-for-byte reproducible")
    output = ROOT / "dist" / "release" / "first"
    wheel, = output.glob("*.whl")
    with ZipFile(wheel) as archive:
        metadata_path, = [name for name in archive.namelist() if name.endswith(".dist-info/METADATA")]
        metadata = Parser().parsestr(archive.read(metadata_path).decode())
        if metadata["Version"] != "0.4.0" or metadata["Requires-Python"] != ">=3.10":
            raise RuntimeError("unexpected release metadata")
    info = {"commit": commit, "source_date_epoch": int(epoch), "python": sys.version.split()[0],
            "tools": {name: version(name) for name in (
                "build", "hatchling", "packaging", "pathspec", "pluggy", "pyproject-hooks",
                "tomlkit", "trove-classifiers")}, "reproducible": True}
    (output / "BUILD-INFO.json").write_text(json.dumps(info, indent=2, sort_keys=True) + "\n")
    artifact_sets[0]["BUILD-INFO.json"] = hashlib.sha256((output / "BUILD-INFO.json").read_bytes()).hexdigest()
    (output / "SHA256SUMS").write_text("".join(
        f"{digest}  {name}\n" for name, digest in sorted(artifact_sets[0].items())))
    print((output / "SHA256SUMS").read_text())


if __name__ == "__main__":
    main()
