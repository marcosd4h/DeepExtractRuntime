"""Module profile formatting for the session-start hook.

Extracted from inject-module-context.py to improve maintainability.
"""

from __future__ import annotations


def format_profile_line(name: str, profile: dict) -> str:
    """Format a module profile into a compact single-line summary."""
    lib = profile.get("library_profile", {})
    api = profile.get("api_profile", {})
    comp = profile.get("complexity_profile", {})

    noise_pct = int(lib.get("noise_ratio", 0) * 100)
    breakdown = lib.get("breakdown", {})
    top3_libs = " ".join(
        f"{k}:{v}" for k, v in list(breakdown.items())[:3]
    )

    dang_funcs = api.get("dangerous_api_functions", 0)
    api_cats = {
        k.replace("_api_count", ""): v
        for k, v in api.items()
        if k.endswith("_api_count") and v > 0
    }
    cat_str = " ".join(
        f"{k}:{v}"
        for k, v in sorted(api_cats.items(), key=lambda x: -x[1])
    )

    surface = api.get("import_surface", {})
    techs = [
        t.upper()
        for t in ("com", "rpc", "winrt", "named_pipes")
        if surface.get(f"{t}_present")
    ]

    loops = comp.get("functions_with_loops", 0)
    avg_asm = comp.get("avg_asm_size", 0)
    max_asm = comp.get("max_asm_size", 0)

    parts = [
        f"{noise_pct}% library ({top3_libs})",
        (
            f"{dang_funcs} dangerous-API funcs ({cat_str})"
            if dang_funcs
            else "no dangerous APIs"
        ),
        "+".join(techs) if techs else "no IPC surface",
        f"loops:{loops} avg-asm:{avg_asm} max-asm:{max_asm}",
    ]
    return f"- **{name}**: {' | '.join(parts)}"


__all__ = ["format_profile_line"]
