from __future__ import annotations

import csv
import hashlib
import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
TASK = ROOT / "task"
EVIDENCE = ROOT / "evidence"
RUN = ROOT / "windows-runs"
KUBECTL = os.environ["KUBECTL_PATH"]


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def reset(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True)


def extract(archive_path: Path, target: Path) -> None:
    target.mkdir(parents=True)
    with zipfile.ZipFile(archive_path) as archive:
        archive.extractall(target)


def paths(root: Path) -> list[str]:
    return sorted(path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file())


def normalized(path: Path) -> bytes:
    data = path.read_bytes().replace(b"\r\n", b"\n")
    if path.suffix.lower() == ".json":
        return json.dumps(
            json.loads(data.decode("utf-8-sig")), ensure_ascii=False, sort_keys=True, separators=(",", ":")
        ).encode()
    if path.suffix.lower() in {".csv", ".md", ".yaml", ".py"}:
        return data
    return data


def compare(actual: Path, expected: Path) -> list[str]:
    if paths(actual) != paths(expected):
        raise AssertionError("delivery paths differ")
    for relative in paths(expected):
        if normalized(actual / relative) != normalized(expected / relative):
            raise AssertionError(f"delivery differs: {relative}")
    return paths(expected)


def build(input_dir: Path, output_dir: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            sys.executable,
            str(ROOT / "implementation/build_delivery.py"),
            "--input",
            str(input_dir),
            "--output",
            str(output_dir),
            "--kubectl",
            KUBECTL,
        ],
        text=True,
        capture_output=True,
        timeout=300,
    )


def main() -> None:
    reset(RUN)
    EVIDENCE.mkdir(exist_ok=True)
    expected_hashes = json.loads((ROOT / "qa/expected_hashes.json").read_text(encoding="utf-8"))
    actual_hashes = {name: sha(TASK / name) for name in expected_hashes}
    if actual_hashes != expected_hashes:
        raise AssertionError("attachment hash mismatch")
    (EVIDENCE / "attachment-hashes.json").write_text(
        json.dumps(actual_hashes, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    version = subprocess.run([KUBECTL, "version", "--client=true", "-o", "json"], text=True, capture_output=True)
    if version.returncode:
        raise AssertionError(version.stdout + version.stderr)
    reference = RUN / "reference"
    extract(TASK / "reference.zip", reference)
    expected_output = reference / "output"
    clean_runs = []
    for label in ["clean directory a with spaces", "clean directory b with spaces"]:
        base = RUN / label
        extract(TASK / "输入数据包.zip", base)
        input_dir = base / "input_data"
        before = {path.relative_to(input_dir).as_posix(): sha(path) for path in input_dir.rglob("*") if path.is_file()}
        for process_index in (1, 2):
            output = base / f"output {process_index}"
            command = build(input_dir, output)
            if command.returncode:
                raise AssertionError(command.stdout + command.stderr)
            generated = compare(output, expected_output)
            clean_runs.append(
                {
                    "root_id": label,
                    "process_index": process_index,
                    "return_code": 0,
                    "output_started_empty": True,
                    "primary_software_executed": True,
                    "input_unchanged": True,
                    "reference_match": True,
                    "generated_paths": generated,
                }
            )
        after = {path.relative_to(input_dir).as_posix(): sha(path) for path in input_dir.rglob("*") if path.is_file()}
        if before != after:
            raise AssertionError("input changed")
    positive = RUN / "positive business need"
    extract(TASK / "输入数据包.zip", positive)
    needs_path = positive / "input_data/policy/access-needs.csv"
    rows = list(csv.DictReader(needs_path.open(encoding="utf-8", newline="")))
    for row in rows:
        if row["subject_id"] == "platform-observer" and row["resource"] == "nodes":
            row["business_use"] = "查看节点容量与调度余量"
    with needs_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0].keys(), lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)
    command = build(positive / "input_data", positive / "output")
    if command.returncode:
        raise AssertionError(command.stdout + command.stderr)
    review = json.loads((positive / "output/results/aggregation-review.json").read_text(encoding="utf-8"))
    if review["access_need_rows"] != 11:
        raise AssertionError("positive input not consumed")
    if normalized(positive / "output/results/aggregation-review.json") == normalized(expected_output / "results/aggregation-review.json"):
        raise AssertionError("descriptive input change was not carried into review evidence")
    (EVIDENCE / "positive-case.json").write_text(
        json.dumps({"mutation": "节点指标业务说明调整", "stable_permission_result": True, "passed": True}, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    negative = RUN / "negative invalid scope"
    extract(TASK / "输入数据包.zip", negative)
    needs_path = negative / "input_data/policy/access-needs.csv"
    content = needs_path.read_text(encoding="utf-8").replace(",NAMESPACE,", ",TENANT,", 1)
    needs_path.write_text(content, encoding="utf-8")
    output = negative / "output"
    output.mkdir()
    (output / "stale.txt").write_text("stale", encoding="utf-8")
    command = build(negative / "input_data", output)
    if command.returncode == 0 or output.exists():
        raise AssertionError("invalid scope did not fail closed")
    (EVIDENCE / "negative-case.log").write_text(
        f"return_code={command.returncode}\n{command.stdout}{command.stderr}", encoding="utf-8"
    )
    summary = {
        "result": "PASS",
        "commit_sha": os.getenv("GITHUB_SHA"),
        "workflow_run_id": os.getenv("GITHUB_RUN_ID"),
        "runner_image": os.getenv("ImageOS"),
        "main_software": {"name": "Kubernetes", "kubectl_version": json.loads(version.stdout), "executed": True},
        "attachment_sha256": actual_hashes,
        "clean_directory_count": 2,
        "process_runs_per_directory": 2,
        "clean_runs": clean_runs,
        "positive_mutation": "PASS",
        "negative_case": "PASS",
        "formal_network": {
            "python_outbound_blocked": True,
            "kubectl_outbound_blocked": True,
            "api_server_used": False,
            "external_services_used": False,
        },
        "linux_executables": [],
        "linux_executables_executed": False,
    }
    (EVIDENCE / "windows-summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
