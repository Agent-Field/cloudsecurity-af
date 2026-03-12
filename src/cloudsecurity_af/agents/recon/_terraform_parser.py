from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any


_REF_PATTERN = re.compile(r"\b((?:data\.)?[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*)\b")
_NON_REF_PREFIXES = ("var.", "local.", "each.", "self.", "count.", "path.", "terraform.")

_PROVIDER_MAP = {
    "aws": "aws",
    "azurerm": "azure",
    "azuread": "azure",
    "google": "gcp",
    "kubernetes": "kubernetes",
    "helm": "kubernetes",
    "oci": "oci",
    "alicloud": "alicloud",
}


def _provider_from_type(resource_type: str) -> str:
    prefix = resource_type.split("_")[0] if "_" in resource_type else resource_type
    return _PROVIDER_MAP.get(prefix, prefix)


def _extract_references(config: dict[str, Any]) -> list[str]:
    refs: set[str] = set()
    _walk_for_refs(config, refs)
    return sorted(refs)


def _walk_for_refs(obj: Any, refs: set[str]) -> None:
    if isinstance(obj, str):
        for match in _REF_PATTERN.finditer(obj):
            candidate = match.group(1)
            if not any(candidate.startswith(p) for p in _NON_REF_PREFIXES):
                refs.add(candidate)
    elif isinstance(obj, dict):
        for v in obj.values():
            _walk_for_refs(v, refs)
    elif isinstance(obj, list):
        for item in obj:
            _walk_for_refs(item, refs)


def _sanitize(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: _sanitize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sanitize(item) for item in obj]
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    return str(obj)


# ---------------------------------------------------------------------------
# pyhcl2 AST → Python dict helpers
# ---------------------------------------------------------------------------


def _expr_to_value(expr: Any) -> Any:
    """Convert a pyhcl2 expression AST node to a plain Python value."""
    cls = type(expr).__name__

    if cls == "Literal":
        val = expr.value
        if hasattr(val, "_raw"):
            return val._raw
        return val

    if cls == "ObjectExpression":
        d: dict[str, Any] = {}
        # ObjectExpression has .fields: dict[Identifier|Literal, Expression]
        fields = getattr(expr, "fields", None)
        if isinstance(fields, dict):
            for k, v in fields.items():
                key_str = getattr(k, "name", None) or getattr(getattr(k, "value", k), "_raw", str(k))
                d[str(key_str)] = _expr_to_value(v)
        return d

    if cls == "ArrayExpression":
        values = getattr(expr, "values", [])
        return [_expr_to_value(v) for v in values]

    # FunctionCall, Conditional, TemplateExpr, etc. → stringify
    if hasattr(expr, "value"):
        val = expr.value
        if hasattr(val, "_raw"):
            return val._raw
        return val

    if hasattr(expr, "_raw"):
        return expr._raw

    return str(expr)


def _block_to_dict(block: Any) -> dict[str, Any]:
    """Recursively convert a pyhcl2 Block AST node to a plain dict."""
    result: dict[str, Any] = {}

    # block.attributes: dict[str, Expression]
    attrs = getattr(block, "attributes", {})
    if isinstance(attrs, dict):
        for attr_name, attr_expr in attrs.items():
            result[attr_name] = _expr_to_value(attr_expr)

    # block.blocks: list[Block]  (nested blocks like versioning {}, ingress {}, etc.)
    sub_blocks = getattr(block, "blocks", [])
    if isinstance(sub_blocks, list):
        for sub in sub_blocks:
            sub_name = getattr(getattr(sub, "type", None), "name", "unknown")
            sub_dict = _block_to_dict(sub)
            labels = getattr(sub, "labels", [])
            if labels:
                label_val = getattr(getattr(labels[0], "value", labels[0]), "_raw", str(labels[0]))
                result.setdefault(sub_name, {})[str(label_val)] = sub_dict
            else:
                # If there's already a value for this key, make it a list
                if sub_name in result:
                    existing = result[sub_name]
                    if isinstance(existing, list):
                        existing.append(sub_dict)
                    else:
                        result[sub_name] = [existing, sub_dict]
                else:
                    result[sub_name] = sub_dict

    return result


def parse_terraform_directory(repo_path: str, output_dir: str) -> tuple[str, int, str]:
    """Parse all .tf files under *repo_path* with pyhcl2 and write inventory.json.

    Returns (inventory_json_path, total_resources, iac_type).
    """
    from pyhcl2.parse import parse_file

    repo = Path(repo_path)
    tf_files = sorted(repo.rglob("*.tf"))

    resources: list[dict[str, Any]] = []
    variables: list[dict[str, Any]] = []
    outputs: list[dict[str, Any]] = []
    providers: list[dict[str, Any]] = []
    modules: list[dict[str, Any]] = []

    for tf_file in tf_files:
        rel_path = str(tf_file.relative_to(repo))
        try:
            with open(tf_file, "r") as f:
                module = parse_file(f)
        except Exception:
            continue

        for stmt in module.body:
            block_type_name = getattr(getattr(stmt, "type", None), "name", None)
            if block_type_name is None:
                continue

            labels_raw = getattr(stmt, "labels", [])
            labels = []
            for lab in labels_raw:
                if hasattr(lab, "name"):
                    labels.append(lab.name)
                elif hasattr(lab, "value") and hasattr(lab.value, "_raw"):
                    labels.append(str(lab.value._raw))
                else:
                    labels.append(str(lab))

            if block_type_name == "resource" and len(labels) >= 2:
                rtype, name = labels[0], labels[1]
                cfg = _block_to_dict(stmt)
                resources.append(
                    {
                        "id": f"{rtype}.{name}",
                        "type": rtype,
                        "name": name,
                        "provider": _provider_from_type(rtype),
                        "file_path": rel_path,
                        "line_number": 0,
                        "config": _sanitize(cfg),
                        "references": _extract_references(cfg),
                        "referenced_by": [],
                    }
                )

            elif block_type_name == "data" and len(labels) >= 2:
                dtype, name = labels[0], labels[1]
                cfg = _block_to_dict(stmt)
                resources.append(
                    {
                        "id": f"data.{dtype}.{name}",
                        "type": f"data.{dtype}",
                        "name": name,
                        "provider": _provider_from_type(dtype),
                        "file_path": rel_path,
                        "line_number": 0,
                        "config": _sanitize(cfg),
                        "references": _extract_references(cfg),
                        "referenced_by": [],
                    }
                )

            elif block_type_name == "variable" and len(labels) >= 1:
                vname = labels[0]
                vcfg = _block_to_dict(stmt)
                variables.append(
                    {
                        "name": vname,
                        "type": str(vcfg.get("type", "")) if vcfg.get("type") is not None else None,
                        "default": str(vcfg.get("default", "")) if vcfg.get("default") is not None else None,
                        "description": vcfg.get("description"),
                        "file_path": rel_path,
                    }
                )

            elif block_type_name == "output" and len(labels) >= 1:
                oname = labels[0]
                ocfg = _block_to_dict(stmt)
                outputs.append(
                    {
                        "name": oname,
                        "value": str(ocfg.get("value", "")),
                        "description": ocfg.get("description"),
                        "file_path": rel_path,
                    }
                )

            elif block_type_name == "provider" and len(labels) >= 1:
                pname = labels[0]
                pcfg = _block_to_dict(stmt)
                providers.append(
                    {
                        "name": pname,
                        "region": pcfg.get("region"),
                        "alias": pcfg.get("alias"),
                        "version": None,
                    }
                )

            elif block_type_name == "module" and len(labels) >= 1:
                mname = labels[0]
                mcfg = _block_to_dict(stmt)
                modules.append(
                    {
                        "name": mname,
                        "source": str(mcfg.get("source", "")),
                        "version": mcfg.get("version"),
                        "file_path": rel_path,
                    }
                )

    # Build reverse references
    ref_targets: dict[str, list[str]] = {}
    for r in resources:
        for ref in r.get("references", []):
            ref_targets.setdefault(ref, []).append(r["id"])
    for r in resources:
        r["referenced_by"] = ref_targets.get(r["id"], [])

    inventory = {
        "resources": resources,
        "variables": variables,
        "outputs": outputs,
        "providers": providers,
        "modules": modules,
    }

    os.makedirs(output_dir, exist_ok=True)
    inventory_path = os.path.join(output_dir, "inventory.json")
    with open(inventory_path, "w") as f:
        json.dump(inventory, f, indent=2, default=str)

    return inventory_path, len(resources), "terraform"
