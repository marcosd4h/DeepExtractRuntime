"""Schema parsing and validation for headless batch pipelines.

This module owns three concerns:

1. Define the supported batch step vocabulary (`STEP_REGISTRY`)
2. Parse YAML pipeline definitions into typed dataclasses
3. Validate and resolve modules before execution

It intentionally performs only lightweight planning work. Actual execution
lives in :mod:`helpers.pipeline_executor`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from .config import get_config_value
from .db_paths import DB_NAME_RE
from .errors import ErrorCode, ScriptError
from .script_runner import get_workspace_root
from .validation import ValidationResult, quick_validate, validate_analysis_db

try:  # pragma: no cover - exercised indirectly by CLI/tests
    import yaml
except ImportError:  # pragma: no cover - handled at runtime
    yaml = None


StepKind = Literal["triage_goal", "security_goal", "security_scan", "skill_group"]
ValueKind = Literal["bool", "int", "str"]

_TIMESTAMP_FMT = "%Y%m%d_%H%M%S"


@dataclass(frozen=True)
class OptionSpec:
    """Validation contract for one step option."""

    kind: ValueKind
    description: str
    minimum: int | None = None


@dataclass(frozen=True)
class StepConfig:
    """Metadata for a supported top-level pipeline step."""

    name: str
    kind: StepKind
    description: str
    goal: str | None = None
    valid_options: dict[str, OptionSpec] = field(default_factory=dict)


@dataclass(frozen=True)
class StepDef:
    """A parsed step entry from the YAML file."""

    name: str
    options: dict[str, Any]
    config: StepConfig

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "options": self.options,
            "kind": self.config.kind,
            "description": self.config.description,
        }


@dataclass(frozen=True)
class PipelineSettings:
    """Execution settings after config defaults + YAML overrides are merged."""

    continue_on_error: bool
    max_workers: int
    step_timeout: int
    parallel_modules: bool | int
    max_module_workers: int
    no_cache: bool

    @property
    def module_workers(self) -> int:
        """Return the effective module-level concurrency."""
        if self.parallel_modules is False:
            return 1
        if self.parallel_modules is True:
            return max(1, self.max_module_workers)
        return max(1, int(self.parallel_modules))

    def to_dict(self) -> dict[str, Any]:
        return {
            "continue_on_error": self.continue_on_error,
            "max_workers": self.max_workers,
            "step_timeout": self.step_timeout,
            "parallel_modules": self.parallel_modules,
            "max_module_workers": self.max_module_workers,
            "no_cache": self.no_cache,
            "module_workers": self.module_workers,
        }


@dataclass(frozen=True)
class PipelineDef:
    """Fully parsed pipeline definition."""

    name: str
    source_path: str
    modules: list[str] | Literal["all"]
    steps: list[StepDef]
    settings: PipelineSettings
    output: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "source_path": self.source_path,
            "modules": self.modules,
            "steps": [step.to_dict() for step in self.steps],
            "settings": self.settings.to_dict(),
            "output": self.output,
        }


@dataclass(frozen=True)
class ResolvedModule:
    """A module name resolved to a concrete analysis DB path."""

    module_name: str
    db_path: str

    def to_dict(self) -> dict[str, str]:
        return {"module_name": self.module_name, "db_path": self.db_path}


STEP_REGISTRY: dict[str, StepConfig] = {
    "triage": StepConfig(
        name="triage",
        kind="triage_goal",
        goal="triage",
        description="Classify functions and discover attack surface.",
        valid_options={
            # Compatibility knob for the proposed YAML format. Current
            # implementation treats triage as the quick path already.
            "quick": OptionSpec("bool", "Compatibility alias for standard triage mode."),
        },
    ),
    "security": StepConfig(
        name="security",
        kind="triage_goal",
        goal="security",
        description="Run triage plus ranked entrypoint dossiers and taint.",
        valid_options={
            "top": OptionSpec("int", "Number of ranked entry points to prioritize.", minimum=1),
        },
    ),
    "full-analysis": StepConfig(
        name="full-analysis",
        kind="triage_goal",
        goal="full",
        description="Run the full module analysis pipeline.",
        valid_options={
            "top": OptionSpec("int", "Number of ranked entry points to prioritize.", minimum=1),
        },
    ),
    "types": StepConfig(
        name="types",
        kind="triage_goal",
        goal="types",
        description="Reconstruct types and COM interfaces.",
    ),
    "scan": StepConfig(
        name="scan",
        kind="security_scan",
        description="Run the full security scan pipeline or a focused scan mode.",
        valid_options={
            "memory_only": OptionSpec("bool", "Run only memory corruption scanners."),
            "logic_only": OptionSpec("bool", "Run only logic vulnerability scanners."),
            "taint_only": OptionSpec("bool", "Run only taint analysis."),
            "top": OptionSpec("int", "Number of entry points to analyze.", minimum=1),
        },
    ),
    "memory-scan": StepConfig(
        name="memory-scan",
        kind="skill_group",
        description="Run the memory corruption detector scanners.",
        valid_options={
            "top": OptionSpec("int", "Limit each scanner to the top N findings.", minimum=1),
        },
    ),
    "ai-logic-scan": StepConfig(
        name="ai-logic-scan",
        kind="skill_group",
        description="Run the AI-driven logic vulnerability scanner.",
        valid_options={
            "top": OptionSpec("int", "Limit hint scanners to top N findings.", minimum=1),
            "depth": OptionSpec("int", "Callgraph depth limit.", minimum=1),
        },
    ),
    "taint": StepConfig(
        name="taint",
        kind="skill_group",
        description="Run taint analysis on top-ranked entry points.",
        valid_options={
            "top": OptionSpec("int", "Number of entry points to analyze.", minimum=1),
            "depth": OptionSpec("int", "Taint depth to traverse.", minimum=1),
        },
    ),
    "classify": StepConfig(
        name="classify",
        kind="skill_group",
        description="Generate a triage-oriented function classification summary.",
        valid_options={
            "top": OptionSpec("int", "Number of interesting functions to include.", minimum=1),
        },
    ),
    "entrypoints": StepConfig(
        name="entrypoints",
        kind="skill_group",
        description="Discover and rank attack surface entry points.",
        valid_options={
            "top": OptionSpec("int", "Number of ranked entry points to return.", minimum=1),
        },
    ),
    "callgraph": StepConfig(
        name="callgraph",
        kind="skill_group",
        description="Build call graph statistics for the module.",
        valid_options={
            "stats": OptionSpec("bool", "Emit call graph statistics."),
        },
    ),
    "dossiers": StepConfig(
        name="dossiers",
        kind="skill_group",
        description="Build security dossiers for top-ranked entry points.",
        valid_options={
            "top": OptionSpec("int", "Number of entry points to build dossiers for.", minimum=1),
        },
    ),
}

_SETTINGS_SPECS: dict[str, OptionSpec] = {
    "continue_on_error": OptionSpec("bool", "Continue when a module or step fails."),
    "max_workers": OptionSpec("int", "Max in-step worker threads.", minimum=1),
    "step_timeout": OptionSpec("int", "Per-step timeout in seconds.", minimum=1),
    "parallel_modules": OptionSpec(
        "str",
        "Bool or positive int. False = sequential, true = max_module_workers, int = explicit workers.",
    ),
    "max_module_workers": OptionSpec("int", "Max concurrent modules when enabled.", minimum=1),
    "no_cache": OptionSpec("bool", "Force uncached skill execution where supported."),
}


def _workspace_root(workspace_root: str | Path | None = None) -> Path:
    if workspace_root is None:
        return get_workspace_root().resolve()
    return Path(workspace_root).resolve()


def _utc_timestamp() -> str:
    return datetime.now(timezone.utc).strftime(_TIMESTAMP_FMT)


def _safe_pipeline_name(value: str) -> str:
    text = (value or "").strip()
    if not text:
        return "pipeline"
    safe = []
    for ch in text:
        if ch.isalnum() or ch in "._-":
            safe.append(ch)
        elif ch.isspace():
            safe.append("-")
        else:
            safe.append("-")
    name = "".join(safe).strip(".-_")
    return name or "pipeline"


def _coerce_bool(value: Any, *, field_name: str) -> bool:
    if isinstance(value, bool):
        return value
    raise ScriptError(f"{field_name} must be a boolean, got {value!r}", ErrorCode.INVALID_ARGS)


def _coerce_positive_int(value: Any, *, field_name: str, minimum: int = 1) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ScriptError(
            f"{field_name} must be an integer >= {minimum}, got {value!r}",
            ErrorCode.INVALID_ARGS,
        )
    if value < minimum:
        raise ScriptError(
            f"{field_name} must be >= {minimum}, got {value}",
            ErrorCode.INVALID_ARGS,
        )
    return value


def _default_settings() -> PipelineSettings:
    return PipelineSettings(
        continue_on_error=bool(get_config_value("pipeline.continue_on_error", True)),
        max_workers=int(get_config_value("pipeline.max_workers", 4)),
        step_timeout=int(get_config_value("pipeline.default_step_timeout", 300)),
        parallel_modules=get_config_value("pipeline.parallel_modules", False),
        max_module_workers=int(get_config_value("pipeline.max_module_workers", 2)),
        no_cache=bool(get_config_value("pipeline.no_cache", False)),
    )


def _parse_settings(raw: Any) -> PipelineSettings:
    base = _default_settings()
    if raw is None:
        return base
    if not isinstance(raw, dict):
        raise ScriptError(
            "'settings' must be a YAML mapping/object.",
            ErrorCode.INVALID_ARGS,
        )

    unknown = sorted(set(raw) - set(_SETTINGS_SPECS))
    if unknown:
        raise ScriptError(
            f"Unknown pipeline setting(s): {', '.join(unknown)}",
            ErrorCode.INVALID_ARGS,
        )

    continue_on_error = (
        _coerce_bool(raw["continue_on_error"], field_name="settings.continue_on_error")
        if "continue_on_error" in raw
        else base.continue_on_error
    )
    max_workers = (
        _coerce_positive_int(raw["max_workers"], field_name="settings.max_workers")
        if "max_workers" in raw
        else base.max_workers
    )
    step_timeout = (
        _coerce_positive_int(raw["step_timeout"], field_name="settings.step_timeout")
        if "step_timeout" in raw
        else base.step_timeout
    )
    max_module_workers = (
        _coerce_positive_int(
            raw["max_module_workers"],
            field_name="settings.max_module_workers",
        )
        if "max_module_workers" in raw
        else base.max_module_workers
    )
    no_cache = (
        _coerce_bool(raw["no_cache"], field_name="settings.no_cache")
        if "no_cache" in raw
        else base.no_cache
    )

    if "parallel_modules" not in raw:
        parallel_modules = base.parallel_modules
    else:
        value = raw["parallel_modules"]
        if isinstance(value, bool):
            parallel_modules = value
        elif isinstance(value, int) and not isinstance(value, bool):
            if value <= 0:
                raise ScriptError(
                    "settings.parallel_modules must be a positive integer when numeric.",
                    ErrorCode.INVALID_ARGS,
                )
            parallel_modules = value
        else:
            raise ScriptError(
                "settings.parallel_modules must be a boolean or a positive integer.",
                ErrorCode.INVALID_ARGS,
            )

    return PipelineSettings(
        continue_on_error=continue_on_error,
        max_workers=max_workers,
        step_timeout=step_timeout,
        parallel_modules=parallel_modules,
        max_module_workers=max_module_workers,
        no_cache=no_cache,
    )


def _parse_modules(raw: Any) -> list[str] | Literal["all"]:
    if isinstance(raw, str):
        value = raw.strip()
        if not value:
            raise ScriptError("'modules' must not be empty.", ErrorCode.INVALID_ARGS)
        if value.lower() == "all":
            return "all"
        return [value]

    if not isinstance(raw, list) or not raw:
        raise ScriptError(
            "'modules' must be a non-empty list of module names or the string 'all'.",
            ErrorCode.INVALID_ARGS,
        )

    modules: list[str] = []
    for idx, item in enumerate(raw, start=1):
        if not isinstance(item, str) or not item.strip():
            raise ScriptError(
                f"modules[{idx}] must be a non-empty string, got {item!r}",
                ErrorCode.INVALID_ARGS,
            )
        modules.append(item.strip())
    return modules


def _validate_option(step_name: str, option_name: str, value: Any, spec: OptionSpec) -> Any:
    field_name = f"steps.{step_name}.{option_name}"
    if spec.kind == "bool":
        return _coerce_bool(value, field_name=field_name)
    if spec.kind == "int":
        minimum = spec.minimum if spec.minimum is not None else 1
        return _coerce_positive_int(value, field_name=field_name, minimum=minimum)
    if spec.kind == "str":
        if step_name == "parallel_modules":  # defensive; not used for step options
            return value
        if not isinstance(value, str):
            raise ScriptError(
                f"{field_name} must be a string, got {value!r}",
                ErrorCode.INVALID_ARGS,
            )
        return value
    raise ScriptError(
        f"Unsupported option validator for {field_name}: {spec.kind}",
        ErrorCode.UNKNOWN,
    )


def _parse_step(item: Any, index: int) -> StepDef:
    if isinstance(item, str):
        step_name = item.strip()
        raw_options: dict[str, Any] = {}
    elif isinstance(item, dict):
        if len(item) != 1:
            raise ScriptError(
                f"steps[{index}] must contain exactly one step name.",
                ErrorCode.INVALID_ARGS,
            )
        step_name, raw_value = next(iter(item.items()))
        if not isinstance(step_name, str) or not step_name.strip():
            raise ScriptError(
                f"steps[{index}] has an invalid step name: {step_name!r}",
                ErrorCode.INVALID_ARGS,
            )
        if raw_value is None:
            raw_options = {}
        elif isinstance(raw_value, dict):
            raw_options = dict(raw_value)
        else:
            raise ScriptError(
                f"steps[{index}] options for '{step_name}' must be a mapping/object.",
                ErrorCode.INVALID_ARGS,
            )
    else:
        raise ScriptError(
            f"steps[{index}] must be a string or single-key mapping, got {item!r}",
            ErrorCode.INVALID_ARGS,
        )

    if step_name not in STEP_REGISTRY:
        available = ", ".join(sorted(STEP_REGISTRY))
        raise ScriptError(
            f"Unknown pipeline step '{step_name}'. Available steps: {available}",
            ErrorCode.INVALID_ARGS,
        )

    config = STEP_REGISTRY[step_name]
    unknown_options = sorted(set(raw_options) - set(config.valid_options))
    if unknown_options:
        raise ScriptError(
            f"Unknown option(s) for step '{step_name}': {', '.join(unknown_options)}",
            ErrorCode.INVALID_ARGS,
        )

    normalized_options: dict[str, Any] = {}
    for option_name, option_value in raw_options.items():
        normalized_options[option_name] = _validate_option(
            step_name,
            option_name,
            option_value,
            config.valid_options[option_name],
        )

    if step_name == "scan":
        enabled_modes = sum(
            1
            for key in ("memory_only", "logic_only", "taint_only")
            if normalized_options.get(key) is True
        )
        if enabled_modes > 1:
            raise ScriptError(
                "The 'scan' step accepts at most one of memory_only, logic_only, or taint_only.",
                ErrorCode.INVALID_ARGS,
            )

    return StepDef(name=step_name, options=normalized_options, config=config)


def load_pipeline(yaml_path: str | Path) -> PipelineDef:
    """Parse a YAML pipeline definition into a typed :class:`PipelineDef`.

    Structural validation happens here. Filesystem validation lives in
    :func:`validate_pipeline`.
    """
    if yaml is None:
        raise ScriptError(
            "PyYAML is required for batch pipelines. Install dependency 'pyyaml>=6.0'.",
            ErrorCode.NO_DATA,
        )

    path = Path(yaml_path).expanduser().resolve()
    if not path.exists():
        raise ScriptError(f"Pipeline file not found: {path}", ErrorCode.NOT_FOUND)

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ScriptError(f"Failed to read pipeline file {path}: {exc}", ErrorCode.NOT_FOUND) from exc
    except Exception as exc:
        raise ScriptError(f"Failed to parse YAML in {path}: {exc}", ErrorCode.PARSE_ERROR) from exc

    if raw is None:
        raise ScriptError(f"Pipeline file is empty: {path}", ErrorCode.INVALID_ARGS)
    if not isinstance(raw, dict):
        raise ScriptError("Pipeline root must be a YAML mapping/object.", ErrorCode.INVALID_ARGS)

    allowed_keys = {"name", "modules", "steps", "settings", "output"}
    unknown_keys = sorted(set(raw) - allowed_keys)
    if unknown_keys:
        raise ScriptError(
            f"Unknown top-level pipeline key(s): {', '.join(unknown_keys)}",
            ErrorCode.INVALID_ARGS,
        )

    if "modules" not in raw:
        raise ScriptError("Pipeline is missing required key 'modules'.", ErrorCode.INVALID_ARGS)
    if "steps" not in raw:
        raise ScriptError("Pipeline is missing required key 'steps'.", ErrorCode.INVALID_ARGS)

    pipeline_name = _safe_pipeline_name(str(raw.get("name") or path.stem))
    modules = _parse_modules(raw["modules"])

    raw_steps = raw["steps"]
    if not isinstance(raw_steps, list) or not raw_steps:
        raise ScriptError(
            "'steps' must be a non-empty list of pipeline steps.",
            ErrorCode.INVALID_ARGS,
        )
    steps = [_parse_step(item, idx) for idx, item in enumerate(raw_steps, start=1)]

    settings = _parse_settings(raw.get("settings"))
    output = str(raw.get("output") or ".agent/workspace/batch_{name}_{timestamp}")

    return PipelineDef(
        name=pipeline_name,
        source_path=str(path),
        modules=modules,
        steps=steps,
        settings=settings,
        output=output,
    )


def _resolve_all_modules_from_tracking(workspace_root: Path) -> list[ResolvedModule]:
    from .analyzed_files_db import open_analyzed_files_db
    from .db_paths import resolve_tracking_db

    tracking_db = resolve_tracking_db(workspace_root)
    if not tracking_db:
        return []

    resolved: list[ResolvedModule] = []
    seen_paths: set[str] = set()
    with open_analyzed_files_db(tracking_db) as db:
        for rec in db.get_all():
            if getattr(rec, "status", None) != "COMPLETE":
                continue
            analysis_db_path = getattr(rec, "analysis_db_path", None)
            if not analysis_db_path:
                continue

            candidates = [
                workspace_root / analysis_db_path,
                workspace_root / "extracted_dbs" / analysis_db_path,
                workspace_root / "extracted_dbs" / Path(analysis_db_path).name,
            ]
            db_path = next((str(candidate.resolve()) for candidate in candidates if candidate.exists()), None)
            if not db_path or db_path in seen_paths:
                continue

            module_name = getattr(rec, "file_name", None) or Path(db_path).name
            resolved.append(ResolvedModule(module_name=module_name, db_path=db_path))
            seen_paths.add(db_path)
    return resolved


def _resolve_all_modules_from_filesystem(workspace_root: Path) -> list[ResolvedModule]:
    from .individual_analysis_db import open_individual_analysis_db

    extracted_dbs = workspace_root / "extracted_dbs"
    if not extracted_dbs.is_dir():
        return []

    resolved: list[ResolvedModule] = []
    for candidate in sorted(extracted_dbs.glob("*.db")):
        if candidate.name.lower() == "analyzed_files.db":
            continue

        module_name = candidate.name
        try:
            with open_individual_analysis_db(str(candidate)) as db:
                file_info = db.get_file_info()
                if file_info and getattr(file_info, "file_name", None):
                    module_name = file_info.file_name
                else:
                    match = DB_NAME_RE.match(candidate.name)
                    module_name = match.group(1) if match else candidate.stem
        except Exception:
            match = DB_NAME_RE.match(candidate.name)
            module_name = match.group(1) if match else candidate.stem

        resolved.append(
            ResolvedModule(module_name=module_name, db_path=str(candidate.resolve()))
        )
    return resolved


def resolve_modules(
    module_list: list[str] | Literal["all"] | str,
    workspace_root: str | Path | None = None,
) -> list[ResolvedModule]:
    """Resolve module names into concrete analysis DB paths."""
    from .command_validation import validate_module

    root = _workspace_root(workspace_root)

    if isinstance(module_list, str) and module_list.lower() == "all":
        module_list = "all"

    if module_list == "all":
        resolved = _resolve_all_modules_from_tracking(root)
        if not resolved:
            resolved = _resolve_all_modules_from_filesystem(root)
        if not resolved:
            raise ScriptError(
                f"No analysis modules found under {root / 'extracted_dbs'}",
                ErrorCode.NO_DATA,
            )
        return sorted(resolved, key=lambda item: item.module_name.lower())

    modules = module_list if isinstance(module_list, list) else [module_list]
    resolved: list[ResolvedModule] = []
    seen_paths: set[str] = set()
    for module_name in modules:
        result = validate_module(module_name, root)
        if not result.ok:
            raise ScriptError(result.errors[0], result.error_codes[0])
        db_path = str(Path(result.resolved["db_path"]).resolve())
        if db_path in seen_paths:
            continue
        resolved.append(ResolvedModule(module_name=module_name, db_path=db_path))
        seen_paths.add(db_path)
    return resolved


def validate_pipeline(
    pipeline_def: PipelineDef,
    workspace_root: str | Path | None = None,
    *,
    quick: bool = False,
) -> ValidationResult:
    """Validate module availability, DB integrity, and output path semantics.

    Parameters
    ----------
    quick:
        When True, use ``quick_validate()`` (file-exists + has-functions-table)
        instead of the full ``PRAGMA integrity_check``.  Much faster for
        dry-run and validation-only workflows.
    """
    root = _workspace_root(workspace_root)
    result = ValidationResult()

    try:
        resolved_modules = resolve_modules(pipeline_def.modules, root)
    except ScriptError as exc:
        result.add_error(str(exc))
        return result

    for module in resolved_modules:
        if quick:
            if not quick_validate(module.db_path):
                result.add_error(
                    f"{module.module_name}: DB failed quick validation "
                    f"(missing or corrupt: {module.db_path})"
                )
        else:
            db_validation = validate_analysis_db(module.db_path)
            if not db_validation.ok:
                for err in db_validation.errors:
                    result.add_error(f"{module.module_name}: {err}")
            for warning in db_validation.warnings:
                result.add_warning(f"{module.module_name}: {warning}")

    rendered_output = render_output_path(pipeline_def.output, pipeline_def.name, root)
    try:
        rendered_output.relative_to(root)
    except ValueError:
        result.add_warning(
            f"Output path is outside the workspace root: {rendered_output}"
        )

    return result


def render_output_path(
    output_template: str,
    pipeline_name: str,
    workspace_root: str | Path | None = None,
    *,
    timestamp: str | None = None,
) -> Path:
    """Render and resolve a pipeline output directory template.

    Relative paths are resolved against the workspace root, except for the
    historical shorthand `workspace/...`, which is resolved under `.agent/`
    so it lands in `.agent/workspace/...` alongside existing run directories.
    """
    root = _workspace_root(workspace_root)
    stamp = timestamp or _utc_timestamp()
    rendered = output_template.format(timestamp=stamp, name=_safe_pipeline_name(pipeline_name))
    rendered_path = Path(rendered)

    if rendered_path.is_absolute():
        return rendered_path.resolve()

    parts = rendered_path.parts
    if parts and parts[0] == "workspace":
        return (root / ".agent" / rendered_path).resolve()

    return (root / rendered_path).resolve()


__all__ = [
    "OptionSpec",
    "PipelineDef",
    "PipelineSettings",
    "ResolvedModule",
    "STEP_REGISTRY",
    "StepConfig",
    "StepDef",
    "load_pipeline",
    "render_output_path",
    "resolve_modules",
    "validate_pipeline",
]
