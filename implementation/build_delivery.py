from __future__ import annotations

import argparse
import csv
import json
import shutil
import subprocess
import sys
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_INPUTS = {
    "README.md",
    "current/rbac-current.yaml",
    "policy/access-needs.csv",
    "policy/review-rules.json",
}


def load_documents(path: Path) -> list[dict]:
    return [item for item in yaml.safe_load_all(path.read_text(encoding="utf-8")) if item]


def write_csv(path: Path, fields: list[str], rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, lineterminator="\n")
        writer.writeheader()
        writer.writerows(rows)


def validate_input(input_dir: Path) -> tuple[list[dict], list[dict], dict]:
    actual = {
        path.relative_to(input_dir).as_posix()
        for path in input_dir.rglob("*")
        if path.is_file()
    }
    if actual != EXPECTED_INPUTS:
        raise ValueError("input file set differs")
    current = load_documents(input_dir / "current/rbac-current.yaml")
    with (input_dir / "policy/access-needs.csv").open(encoding="utf-8", newline="") as handle:
        needs = list(csv.DictReader(handle))
        required = [
            "subject_id",
            "subject_namespace",
            "binding_scope",
            "api_group",
            "resource",
            "subresource",
            "non_resource_url",
            "verbs",
            "business_use",
        ]
        if handle.seekable() and (not needs or list(needs[0]) != required):
            raise ValueError("access needs header differs")
    for row in needs:
        if row["binding_scope"] not in {"NAMESPACE", "CLUSTER"}:
            raise ValueError("invalid binding scope")
        if bool(row["resource"]) == bool(row["non_resource_url"]):
            raise ValueError("resource request shape differs")
    policy = json.loads((input_dir / "policy/review-rules.json").read_text(encoding="utf-8"))
    required_policy = {
        "schema_version",
        "aggregate_label",
        "aggregate_value",
        "aggregate_role",
        "forbidden_resources",
        "forbidden_verbs",
        "forbid_wildcards",
        "tenant_binding_kind",
        "platform_binding_kind",
        "required_handover_note",
    }
    if set(policy) != required_policy or policy["schema_version"] != 1:
        raise ValueError("review rules differ")
    return current, needs, policy


def object_key(item: dict) -> tuple[str, str, str]:
    metadata = item.get("metadata", {})
    return item.get("kind", ""), metadata.get("namespace", ""), metadata.get("name", "")


def rule_rows(documents: list[dict], policy: dict) -> tuple[list[dict], list[str]]:
    fragments = []
    for item in documents:
        if item.get("kind") != "ClusterRole":
            continue
        labels = item.get("metadata", {}).get("labels", {})
        if labels.get(policy["aggregate_label"]) == policy["aggregate_value"]:
            fragments.append(item)
    rows = []
    for item in sorted(fragments, key=lambda value: value["metadata"]["name"]):
        role_name = item["metadata"]["name"]
        for rule in item.get("rules", []):
            verbs = "|".join(sorted(rule.get("verbs", [])))
            for resource in rule.get("resources", []):
                rows.append(
                    {
                        "fragment": role_name,
                        "api_group": "|".join(rule.get("apiGroups", [])),
                        "resource": resource,
                        "non_resource_url": "",
                        "verbs": verbs,
                    }
                )
            for url in rule.get("nonResourceURLs", []):
                rows.append(
                    {
                        "fragment": role_name,
                        "api_group": "",
                        "resource": "",
                        "non_resource_url": url,
                        "verbs": verbs,
                    }
                )
    return sorted(rows, key=lambda row: tuple(row.values())), sorted(item["metadata"]["name"] for item in fragments)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--kubectl", required=True)
    args = parser.parse_args()
    input_dir = Path(args.input).resolve()
    output_dir = Path(args.output).resolve()
    if output_dir.exists():
        shutil.rmtree(output_dir)
    try:
        current, needs, policy = validate_input(input_dir)
        temp_dir = output_dir.parent / f".{output_dir.name}-building"
        if temp_dir.exists():
            shutil.rmtree(temp_dir)
        temp_dir.mkdir(parents=True)
        bundle_dir = temp_dir / "bundle"
        shutil.copytree(ROOT / "implementation/bundle", bundle_dir)
        rendered_dir = temp_dir / "rendered"
        rendered_dir.mkdir()
        command = subprocess.run(
            [args.kubectl, "kustomize", str(bundle_dir)],
            text=True,
            capture_output=True,
            timeout=120,
        )
        if command.returncode:
            raise ValueError(command.stdout + command.stderr)
        rendered = rendered_dir / "rbac-bundle.yaml"
        rendered.write_text(command.stdout.replace("\r\n", "\n"), encoding="utf-8")
        documents = load_documents(rendered)
        keys = [object_key(item) for item in documents]
        if len(keys) != len(set(keys)):
            raise ValueError("rendered object key duplicated")
        results = temp_dir / "results"
        results.mkdir()
        inventory = [
            {"kind": kind, "namespace": namespace, "name": name}
            for kind, namespace, name in sorted(keys)
        ]
        write_csv(results / "object-inventory.csv", ["kind", "namespace", "name"], inventory)
        rules, fragments = rule_rows(documents, policy)
        write_csv(
            results / "rule-inventory.csv",
            ["fragment", "api_group", "resource", "non_resource_url", "verbs"],
            rules,
        )
        bindings = []
        for item in documents:
            if item.get("kind") not in {"RoleBinding", "ClusterRoleBinding"}:
                continue
            metadata = item.get("metadata", {})
            for subject in item.get("subjects", []):
                bindings.append(
                    {
                        "binding_kind": item["kind"],
                        "binding_namespace": metadata.get("namespace", ""),
                        "binding_name": metadata.get("name", ""),
                        "subject_namespace": subject.get("namespace", ""),
                        "subject_name": subject.get("name", ""),
                        "role_ref": item.get("roleRef", {}).get("name", ""),
                        "scope": "NAMESPACE" if item["kind"] == "RoleBinding" else "CLUSTER",
                    }
                )
        bindings.sort(key=lambda row: tuple(row.values()))
        write_csv(
            results / "binding-scope.csv",
            ["binding_kind", "binding_namespace", "binding_name", "subject_namespace", "subject_name", "role_ref", "scope"],
            bindings,
        )
        current_role = next(
            item
            for item in current
            if item.get("kind") == "ClusterRole"
            and item.get("metadata", {}).get("name") == "observation-reader-current"
        )
        current_binding = next(
            item
            for item in current
            if item.get("kind") == "ClusterRoleBinding"
            and item.get("metadata", {}).get("name") == "tenant-viewers-current"
        )
        wildcard_present = any(
            "*" in rule.get("apiGroups", []) or "*" in rule.get("resources", [])
            for rule in current_role.get("rules", [])
        )
        tenant_subjects = {
            (subject.get("namespace"), subject.get("name"))
            for subject in current_binding.get("subjects", [])
        }
        if not wildcard_present or tenant_subjects != {("tenant-red", "viewer"), ("tenant-blue", "viewer")}:
            raise ValueError("current risk baseline differs")
        dispositions = [
            {
                "finding_id": "CURRENT-WILDCARD",
                "source_object": "ClusterRole/observation-reader-current",
                "risk": "通配符规则超过观测需要",
                "resolution": "以标记后的只读片段替代",
                "status": "RESOLVED_IN_BUNDLE",
            },
            {
                "finding_id": "TENANT-CLUSTER-BINDING",
                "source_object": "ClusterRoleBinding/tenant-viewers-current",
                "risk": "租户账号获得集群范围绑定",
                "resolution": "改为各租户命名空间RoleBinding",
                "status": "RESOLVED_IN_BUNDLE",
            },
        ]
        write_csv(
            results / "risk-disposition.csv",
            ["finding_id", "source_object", "risk", "resolution", "status"],
            dispositions,
        )
        aggregate = next(
            item
            for item in documents
            if item.get("kind") == "ClusterRole" and item.get("metadata", {}).get("name") == policy["aggregate_role"]
        )
        selectors = aggregate.get("aggregationRule", {}).get("clusterRoleSelectors", [])
        forbidden = []
        for row in rules:
            values = [row["api_group"], row["resource"], row["verbs"]]
            if policy["forbid_wildcards"] and any("*" in value for value in values):
                forbidden.append(f"wildcard:{row['fragment']}")
            if row["resource"] in policy["forbidden_resources"]:
                forbidden.append(f"resource:{row['resource']}")
            for verb in row["verbs"].split("|"):
                if verb in policy["forbidden_verbs"]:
                    forbidden.append(f"verb:{verb}")
        requested_permissions = sorted(
            [
                {
                    "subject_id": row["subject_id"],
                    "binding_scope": row["binding_scope"],
                    "api_group": row["api_group"],
                    "resource": row["resource"],
                    "subresource": row["subresource"],
                    "non_resource_url": row["non_resource_url"],
                    "verbs": sorted(row["verbs"].split("|")),
                    "business_use": row["business_use"],
                }
                for row in needs
            ],
            key=lambda row: json.dumps(row, sort_keys=True),
        )
        need_rule_set = {
            (
                row["api_group"],
                f"{row['resource']}/{row['subresource']}" if row["subresource"] else row["resource"],
                row["non_resource_url"],
                tuple(sorted(row["verbs"].split("|"))),
            )
            for row in needs
        }
        rendered_rule_set = {
            (
                row["api_group"],
                row["resource"],
                row["non_resource_url"],
                tuple(row["verbs"].split("|")),
            )
            for row in rules
        }
        if need_rule_set != rendered_rule_set:
            raise ValueError("rendered rules differ from access needs")
        review = {
            "review_scope": "LOCAL_RENDERED_MANIFEST_ONLY",
            "aggregate_role": policy["aggregate_role"],
            "aggregate_role_has_rules": "rules" in aggregate,
            "selectors": selectors,
            "selected_fragments": fragments,
            "forbidden_findings": forbidden,
            "access_need_rows": len(needs),
            "requested_permissions": requested_permissions,
            "note": "静态清单不能证明聚合控制器或API Server中的实际授权",
        }
        (results / "aggregation-review.json").write_text(
            json.dumps(review, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        handover = {
            "status": "READY",
            "review_scope": "LOCAL_RENDERED_MANIFEST_ONLY",
            "apply_owner": "现场管理员",
            "post_apply_checks": ["等待聚合控制器完成", "核查实际授权"],
            "object_count": len(inventory),
            "rule_count": len(rules),
            "binding_count": len(bindings),
            "resolved_risk_count": len(dispositions),
        }
        (results / "handover.json").write_text(
            json.dumps(handover, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        (temp_dir / "tools").mkdir()
        shutil.copy2(Path(__file__), temp_dir / "tools/build_delivery.py")
        (temp_dir / "HANDOVER.md").write_text(
            "# 观测权限清单交接\n\n"
            "本次结论只针对rendered/rbac-bundle.yaml中的本地清单，不代表集群授权已经生效。\n\n"
            "现场管理员负责在维护窗口应用bundle目录中的清单，等待聚合控制器完成，再核查实际授权。\n",
            encoding="utf-8",
        )
        temp_dir.replace(output_dir)
        return 0
    except Exception as exc:
        temp_dir = output_dir.parent / f".{output_dir.name}-building"
        if temp_dir.exists():
            shutil.rmtree(temp_dir)
        if output_dir.exists():
            shutil.rmtree(output_dir)
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
