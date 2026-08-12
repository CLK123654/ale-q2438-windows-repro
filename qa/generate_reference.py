from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EVIDENCE = ROOT / "evidence"
WORK = ROOT / "work-reference"
if WORK.exists():
    shutil.rmtree(WORK)
WORK.mkdir()
EVIDENCE.mkdir(exist_ok=True)
with zipfile.ZipFile(ROOT / "task/输入数据包.zip") as archive:
    archive.extractall(WORK)
command = subprocess.run(
    [
        sys.executable,
        str(ROOT / "implementation/build_delivery.py"),
        "--input",
        str(WORK / "input_data"),
        "--output",
        str(WORK / "output"),
        "--kubectl",
        os.environ["KUBECTL_PATH"],
    ],
    text=True,
    capture_output=True,
    timeout=300,
)
if command.returncode:
    raise SystemExit(command.stdout + command.stderr)
with zipfile.ZipFile(
    EVIDENCE / "reference-candidate.zip", "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
) as archive:
    for path in sorted((WORK / "output").rglob("*")):
        if path.is_file():
            archive.write(path, path.relative_to(WORK).as_posix())
(EVIDENCE / "reference-generation.json").write_text(
    json.dumps(
        {
            "result": "PASS",
            "commit_sha": os.getenv("GITHUB_SHA"),
            "workflow_run_id": os.getenv("GITHUB_RUN_ID"),
            "reference_members": sorted(
                path.relative_to(WORK).as_posix()
                for path in (WORK / "output").rglob("*")
                if path.is_file()
            ),
        },
        indent=2,
    )
    + "\n",
    encoding="utf-8",
)
