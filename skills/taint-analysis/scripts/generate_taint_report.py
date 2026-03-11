#!/usr/bin/env python3
"""Generate taint analysis reports in JSON or markdown format.

Consumes the structured output from ``trace_taint_forward.py`` and
``trace_taint_backward.py`` and produces a unified vulnerability-research
report highlighting:
  - Sink findings (what sensitive APIs are reached)
  - Guards to bypass on each path
  - Logic effects of tainted data
  - Backward origin context (where tainted data comes from)

Usage (typically called by taint_function.py, not directly):
    python generate_taint_report.py --forward <json_path> [--backward <json_path>] [--json]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_AGENT_DIR = str(Path(__file__).resolve().parents[3])
if _AGENT_DIR not in sys.path:
    sys.path.insert(0, _AGENT_DIR)

from helpers.calling_conventions import param_name_for  # noqa: E402
from helpers.errors import ErrorCode, emit_error, safe_parse_args  # noqa: E402
from helpers.json_output import emit_json  # noqa: E402


# ---------------------------------------------------------------------------
# Report assembly
# ---------------------------------------------------------------------------

def build_report(
    forward_data: dict | None,
    backward_data: dict | None,
    direction: str = "forward",
) -> dict:
    """Merge forward and backward results into a unified report dict."""
    report: dict = {"status": "ok", "direction": direction}

    if forward_data and forward_data.get("status") == "ok":
        report["function"] = forward_data["function"]
        report["tainted_params"] = forward_data.get("tainted_params", [])
        report["forward_findings"] = forward_data.get("findings", [])
        report["logic_effects"] = forward_data.get("logic_effects", {})
        report["forward_summary"] = forward_data.get("summary", {})

        if forward_data.get("cross_module"):
            report["cross_module"] = forward_data["cross_module"]
        if forward_data.get("taint_context"):
            report["taint_context"] = forward_data["taint_context"]

    elif backward_data and backward_data.get("status") == "ok":
        report["function"] = backward_data["function"]
        report["tainted_params"] = backward_data.get("tainted_params", [])

    if backward_data and backward_data.get("status") == "ok":
        report["backward_callers"] = backward_data.get("callers", [])
        report["backward_summary"] = backward_data.get("summary", {})

    fwd = report.get("forward_summary", {})
    bwd = report.get("backward_summary", {})
    cm = report.get("cross_module", {})
    report["summary"] = {
        "total_sinks": fwd.get("total_sinks", 0),
        "critical": fwd.get("critical", 0),
        "high": fwd.get("high", 0),
        "medium": fwd.get("medium", 0),
        "low": fwd.get("low", 0),
        "total_callers": bwd.get("total_callers", 0),
        "high_risk_origins": bwd.get("high_risk_origins", 0),
        "cross_module_findings": cm.get("cross_module_findings", 0),
        "trust_escalations": cm.get("trust_escalations", 0),
        "boundary_types": cm.get("boundary_types", []),
    }
    return report


# ---------------------------------------------------------------------------
# Markdown renderer
# ---------------------------------------------------------------------------

def render_markdown(report: dict) -> str:
    """Render the report dict as a human-readable markdown string."""
    lines: list[str] = []
    func = report.get("function", {})
    fname = func.get("function_name", "?")
    module = func.get("module_name", "?")
    params = report.get("tainted_params", [])
    pnames = ", ".join(param_name_for(p) for p in params)
    direction = report.get("direction", "forward")

    lines.append(f"=== Taint Analysis: {fname} ===")
    lines.append(f"Module: {module}")
    lines.append(f"Signature: {func.get('function_signature', '?')}")
    lines.append(f"Direction: {direction} | Tainted: {pnames}")
    lines.append("")

    # Forward findings
    findings = report.get("forward_findings", [])
    if findings:
        for i, f in enumerate(findings, 1):
            lines.append(f"--- FINDING {i}: {f['param_name']} reaches {f['sink']} ({f['sink_category']}) ---")
            lines.append(f"Severity: {f['severity']} ({f['score']:.2f})")
            lines.append(f"Path: {' -> '.join(f['path'])}")

            guards = f.get("guards", [])
            if guards:
                lines.append(f"\nGuards to bypass ({len(guards)}):")
                for gi, g in enumerate(guards, 1):
                    ctrl = "YES" if g["attacker_controllable"] else "NO"
                    lines.append(f"  [{gi}] {g['guard_type'].upper()}: {g['condition']} at L{g['line_number']}")
                    lines.append(f"      Attacker-controllable: {ctrl} (difficulty: {g['bypass_difficulty']})")
                    tainted = g.get("tainted_vars_in_condition", [])
                    if tainted:
                        lines.append(f"      Tainted vars in condition: {', '.join(tainted)}")
                    if g.get("api_in_condition"):
                        lines.append(f"      API: {g['api_in_condition']}")
            lines.append("")
    elif direction in ("forward", "both"):
        lines.append("No dangerous sinks reached by tainted data.")
        lines.append("")

    # Logic effects
    effects = report.get("logic_effects", {})
    if effects:
        lines.append("--- Logic Effects ---")
        for pname, elist in effects.items():
            for e in elist:
                lines.append(f"  {pname}: {e['type'].upper()} at L{e['line']}")
                lines.append(f"    {e['text'][:120]}")
        lines.append("")

    # Backward callers
    callers = report.get("backward_callers", [])
    if callers:
        lines.append("--- Backward Caller Origins ---")
        for c in callers:
            cname = c.get("caller_name", "?")
            if c.get("status") == "external":
                lines.append(f"  {cname} [{c.get('module', '?')}] -- external")
                continue
            for o in c.get("origins", []):
                risk = o.get("risk", "?")
                lines.append(f"  {cname} passes {o['expression']} for param {o['for_param']} "
                             f"-- origin: {o['origin_type']} (risk: {risk})")
        lines.append("")

    # Cross-module context (trust transitions, accumulated guards, boundary info)
    cm = report.get("cross_module", {})
    if cm.get("enabled"):
        lines.append("--- Cross-Module Analysis ---")
        lines.append(f"Cross-module hops: {cm.get('cross_depth', 0)}")
        lines.append(f"Cross-module findings: {cm.get('cross_module_findings', 0)}")
        bt = cm.get("boundary_types", [])
        if bt:
            lines.append(f"Boundary types: {', '.join(bt)}")
        if cm.get("trust_escalations", 0):
            lines.append(f"*** Trust escalations: {cm['trust_escalations']} ***")
        ret_vars = cm.get("return_taint_vars", [])
        if ret_vars:
            lines.append(f"Return-tainted variables: {', '.join(ret_vars)}")
        lines.append("")

    ctx = report.get("taint_context", {})
    if ctx:
        transitions = ctx.get("trust_transitions", [])
        if transitions:
            lines.append("--- Trust Boundary Transitions ---")
            for t in transitions:
                arrow = "ESCALATION" if t.get("transition") == "privilege_escalation" else t.get("transition", "?")
                lines.append(
                    f"  {t['from_module']} ({t['from_trust']}) "
                    f"-[{t.get('boundary_type', '?')}]-> "
                    f"{t['to_module']} ({t['to_trust']}) [{arrow}]"
                )
            lines.append("")

        acc_guards = ctx.get("accumulated_guards", [])
        if acc_guards:
            lines.append(f"--- Accumulated Guards Across Chain ({len(acc_guards)}) ---")
            for gi, g in enumerate(acc_guards[:10], 1):
                ctrl = "YES" if g.get("attacker_controllable") else "NO"
                lines.append(
                    f"  [{gi}] {g.get('guard_type', '?').upper()}: "
                    f"{g.get('condition', '?')[:80]} "
                    f"(controllable: {ctrl})"
                )
            if len(acc_guards) > 10:
                lines.append(f"  ... and {len(acc_guards) - 10} more")
            lines.append("")

    # Cross-module findings (annotated)
    cross_findings = [
        f for f in report.get("forward_findings", [])
        if f.get("cross_module_source")
    ]
    if cross_findings:
        lines.append(f"--- Cross-Module Findings ({len(cross_findings)}) ---")
        for i, f in enumerate(cross_findings, 1):
            cms = f.get("cross_module_source", {})
            bt_label = cms.get("boundary_type", "dll_import")
            escalated = " [TRUST ESCALATED]" if f.get("trust_escalated") else ""
            lines.append(
                f"  [{i}] {f['severity']} ({f['score']:.2f}){escalated} -- "
                f"{f.get('param_name', '?')} reaches {f['sink']} ({f['sink_category']})"
            )
            lines.append(f"      Boundary: {cms.get('from_module', '?')} -[{bt_label}]-> {cms.get('to_module', '?')}")
            pm = cms.get("param_mapping", {})
            if pm:
                mappings = ", ".join(f"a{k}->a{v}" for k, v in pm.items())
                lines.append(f"      Param mapping: {mappings}")
            lines.append(f"      Path: {' -> '.join(f['path'])}")
        lines.append("")

    # Summary
    summary = report.get("summary", {})
    parts = []
    if summary.get("total_sinks", 0):
        parts.append(f"{summary['total_sinks']} sinks")
        severity_parts = []
        for sev in ("critical", "high", "medium", "low"):
            cnt = summary.get(sev, 0)
            if cnt:
                severity_parts.append(f"{sev.upper()}={cnt}")
        if severity_parts:
            parts.append(" ".join(severity_parts))
    if summary.get("cross_module_findings", 0):
        parts.append(f"{summary['cross_module_findings']} cross-module")
    if summary.get("trust_escalations", 0):
        parts.append(f"{summary['trust_escalations']} trust escalations")
    if summary.get("total_callers", 0):
        parts.append(f"{summary['total_callers']} callers")
    if summary.get("high_risk_origins", 0):
        parts.append(f"{summary['high_risk_origins']} high-risk origins")
    if parts:
        lines.append(f"--- Summary: {' | '.join(parts)} ---")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main (standalone invocation)
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Generate taint analysis report.")
    parser.add_argument("--forward", help="Path to forward taint JSON result file")
    parser.add_argument("--backward", help="Path to backward taint JSON result file")
    parser.add_argument("--direction", default="forward", choices=["forward", "backward", "both"])
    parser.add_argument("--json", action="store_true", help="JSON output")
    args = safe_parse_args(parser)

    forward_data = None
    backward_data = None
    if args.forward:
        try:
            with open(args.forward, "r", encoding="utf-8") as fh:
                forward_data = json.load(fh)
        except FileNotFoundError:
            emit_error(f"Forward trace file not found: {args.forward}", ErrorCode.NOT_FOUND)
            return
        except (json.JSONDecodeError, OSError) as exc:
            emit_error(f"Failed to read forward trace: {exc}", ErrorCode.PARSE_ERROR)
            return
    if args.backward:
        try:
            with open(args.backward, "r", encoding="utf-8") as fh:
                backward_data = json.load(fh)
        except FileNotFoundError:
            emit_error(f"Backward trace file not found: {args.backward}", ErrorCode.NOT_FOUND)
            return
        except (json.JSONDecodeError, OSError) as exc:
            emit_error(f"Failed to read backward trace: {exc}", ErrorCode.PARSE_ERROR)
            return

    report = build_report(forward_data, backward_data, direction=args.direction)

    if args.json:
        emit_json(report)
    else:
        print(render_markdown(report))


if __name__ == "__main__":
    main()
