#!/usr/bin/env python3
"""Headless batch pipeline runner for DeepExtractRuntime.

CLI entry point for running, validating, and inspecting batch analysis
pipelines defined in YAML.  Can be invoked directly::

    python .agent/helpers/pipeline_cli.py run config/pipelines/security-sweep.yaml --json
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import replace
from pathlib import Path
from typing import Any

_SCRIPT_DIR = Path(__file__).resolve().parent
_RUNTIME_ROOT = _SCRIPT_DIR.parent
if str(_RUNTIME_ROOT) not in sys.path:
    sys.path.insert(0, str(_RUNTIME_ROOT))

from helpers.errors import ErrorCode, emit_error  # noqa: E402
from helpers.json_output import emit_json  # noqa: E402
from helpers.progress import status_message  # noqa: E402
from helpers.pipeline_executor import execute_pipeline  # noqa: E402
from helpers.pipeline_schema import (  # noqa: E402
    STEP_REGISTRY,
    PipelineDef,
    load_pipeline,
    render_output_path,
    resolve_modules,
    validate_pipeline,
)


def _parse_module_override(raw: str | None) -> list[str] | str | None:
    if raw is None:
        return None
    value = raw.strip()
    if not value:
        raise ValueError("--modules must not be empty")
    if value.lower() == "all":
        return "all"
    modules = [item.strip() for item in value.split(",") if item.strip()]
    if not modules:
        raise ValueError("--modules did not contain any module names")
    return modules


def _apply_overrides(
    pipeline_def: PipelineDef,
    *,
    modules_override: list[str] | str | None = None,
    output_override: str | None = None,
) -> PipelineDef:
    updated = pipeline_def
    if modules_override is not None:
        updated = replace(updated, modules=modules_override)
    if output_override is not None:
        updated = replace(updated, output=output_override)
    return updated


def _print_validation_summary(pipeline_def: PipelineDef) -> None:
    print(f"Pipeline: {pipeline_def.name}")
    print(f"Source:   {pipeline_def.source_path}")
    print(f"Modules:  {pipeline_def.modules}")
    print(f"Steps:    {', '.join(step.name for step in pipeline_def.steps)}")
    print(f"Output:   {pipeline_def.output}")


def _print_step_list() -> None:
    print("Available batch pipeline steps:\n")
    for step_name in sorted(STEP_REGISTRY):
        config = STEP_REGISTRY[step_name]
        options = ", ".join(sorted(config.valid_options)) or "(none)"
        print(f"- {step_name}")
        print(f"  kind: {config.kind}")
        print(f"  desc: {config.description}")
        print(f"  opts: {options}")


def _print_run_summary(result: dict[str, Any]) -> None:
    print(f"Pipeline: {result.get('pipeline_name', '?')}")
    print(f"Status:   {result.get('status', '?')}")
    print(f"Output:   {result.get('output_dir', '?')}")
    print(f"Modules:  {result.get('total_modules', 0)}")
    print(f"Elapsed:  {result.get('total_elapsed_seconds', 0)}s")
    print()

    modules = result.get("modules", {})
    for module_name, module in modules.items():
        print(f"- {module_name}: {module.get('status', '?')} ({module.get('elapsed_seconds', 0)}s)")
        for step in module.get("step_results", []):
            print(
                f"    {step.get('step_name', '?')}: {step.get('status', '?')} "
                f"({step.get('elapsed_seconds', 0)}s)"
            )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run headless analysis pipelines from YAML definitions.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    run_parser = subparsers.add_parser("run", help="Execute a pipeline definition")
    run_parser.add_argument("pipeline_file", help="Path to the pipeline YAML file")
    run_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Resolve modules and steps without executing analysis",
    )
    run_parser.add_argument(
        "--modules",
        help="Override YAML modules with a comma-separated list or 'all'",
    )
    run_parser.add_argument(
        "--output",
        help="Override the YAML output directory template",
    )
    run_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON output",
    )

    validate_parser = subparsers.add_parser("validate", help="Validate a pipeline definition")
    validate_parser.add_argument("pipeline_file", help="Path to the pipeline YAML file")
    validate_parser.add_argument(
        "--modules",
        help="Override YAML modules with a comma-separated list or 'all'",
    )
    validate_parser.add_argument(
        "--output",
        help="Override the YAML output directory template",
    )
    validate_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON output",
    )

    list_parser = subparsers.add_parser("list-steps", help="List supported pipeline steps")
    list_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON output",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "list-steps":
        steps = {
            name: {
                "kind": config.kind,
                "description": config.description,
                "options": sorted(config.valid_options),
            }
            for name, config in sorted(STEP_REGISTRY.items())
        }
        if args.json:
            emit_json({"steps": steps})
            return
        _print_step_list()
        return

    try:
        modules_override = _parse_module_override(getattr(args, "modules", None))
    except ValueError as exc:
        emit_error(str(exc), ErrorCode.INVALID_ARGS)

    try:
        pipeline_def = load_pipeline(args.pipeline_file)
        pipeline_def = _apply_overrides(
            pipeline_def,
            modules_override=modules_override,
            output_override=getattr(args, "output", None),
        )
    except Exception as exc:
        if isinstance(exc, SystemExit):
            raise
        emit_error(str(exc), getattr(exc, "code", ErrorCode.INVALID_ARGS))

    use_quick = args.command == "validate" or getattr(args, "dry_run", False)
    validation = validate_pipeline(pipeline_def, quick=use_quick)
    if not validation.ok:
        emit_error("\n".join(validation.errors), ErrorCode.INVALID_ARGS)
    for warning in validation.warnings:
        status_message(f"WARNING: {warning}")

    if args.command == "validate":
        resolved_modules = resolve_modules(pipeline_def.modules)
        payload = {
            "pipeline": pipeline_def.to_dict(),
            "resolved_modules": [module.to_dict() for module in resolved_modules],
            "rendered_output_dir": str(
                render_output_path(pipeline_def.output, pipeline_def.name)
            ),
            "warnings": validation.warnings,
        }
        if args.json:
            emit_json(payload)
            return
        _print_validation_summary(pipeline_def)
        print()
        print("Resolved modules:")
        for module in resolved_modules:
            print(f"- {module.module_name}: {module.db_path}")
        print(f"\nRendered output: {payload['rendered_output_dir']}")
        return

    try:
        result = execute_pipeline(pipeline_def, dry_run=args.dry_run)
    except Exception as exc:
        if isinstance(exc, SystemExit):
            raise
        emit_error(str(exc), getattr(exc, "code", ErrorCode.UNKNOWN))

    payload = result.to_dict()
    if args.json:
        emit_json(payload)
        return
    _print_run_summary(payload)


if __name__ == "__main__":
    main()
