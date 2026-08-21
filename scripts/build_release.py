from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import tempfile
import time
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXCLUDED_ANYWHERE = {".venv", "__pycache__", ".git"}
EXCLUDED_TOP_LEVEL = {"runtime", "logs", "uat-results"}
EXCLUDED_SUFFIXES = {".pyc", ".sqlite3", ".sqlite3-wal", ".sqlite3-shm"}


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def included(path: Path) -> bool:
    relative = path.relative_to(ROOT)
    if relative.parts and relative.parts[0] in EXCLUDED_TOP_LEVEL:
        return False
    if any(part in EXCLUDED_ANYWHERE or part == ".DS_Store" for part in relative.parts):
        return False
    if any(path.name.endswith(suffix) for suffix in EXCLUDED_SUFFIXES):
        return False
    if ".bak" in path.name or path.name.endswith(".zip"):
        return False
    return path.is_file()


def main() -> None:
    parser = argparse.ArgumentParser(description="Build a clean, checksummed Gateway release ZIP")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    output = (args.output or ROOT.parent / f"Home-Gateway-Stage5-Ops-v1-{version}.zip").resolve()
    if output == ROOT or ROOT in output.parents:
        raise SystemExit("release ZIP must be written outside the source tree")
    files = sorted(path for path in ROOT.rglob("*") if included(path))
    with tempfile.TemporaryDirectory() as directory:
        stage_root = Path(directory) / ROOT.name
        for source in files:
            target = stage_root / source.relative_to(ROOT)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        manifest_files = {
            str(path.relative_to(stage_root)): {"size": path.stat().st_size, "sha256": digest(path)}
            for path in sorted(stage_root.rglob("*")) if path.is_file()
        }
        manifest = {
            "format": 1,
            "product": "WebUI Home Gateway",
            "version": version,
            "built_at": int(time.time()),
            "files": manifest_files,
        }
        (stage_root / "RELEASE_MANIFEST.json").write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        temporary = output.with_suffix(output.suffix + ".tmp")
        output.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(temporary, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(stage_root.rglob("*")):
                if path.is_file():
                    archive.write(path, str(path.relative_to(stage_root.parent)))
        os.replace(temporary, output)
    print(json.dumps({
        "output": str(output), "size": output.stat().st_size, "sha256": digest(output),
        "file_count": len(manifest_files) + 1,
    }, ensure_ascii=False))


if __name__ == "__main__":
    main()
