# FR-002: PDF Report Export

**Status:** Proposed
**Priority:** Medium
**Category:** Reporting / Tooling
**Author:** Runtime Assessment Review
**Date:** 2026-03-16

---

## Problem Statement

All analysis commands produce markdown reports saved to
`extracted_code/<module>/reports/`.  There is no PDF generation
capability in the runtime.  Researchers who need to share findings with
teams, create presentation-ready artifacts, or archive analysis results
in a portable format have no PDF path.

| Command | Current Output |
|---------|----------------|
| `/scan` | `reports/ai_memory_scan_<timestamp>.md` + `.findings.json` |
| `/audit` | `reports/audit_<function>_<timestamp>.md` |
| `/triage` | `reports/triage_<module>_<timestamp>.md` |
| `/full-report` | `reports/full_report_<module>_<timestamp>.md` |
| `/taint` | `reports/ai_taint_scan_<timestamp>.md` + `.findings.json` |
| `/memory-scan` | `reports/ai_memory_scan_<timestamp>.md` + `.findings.json` |
| `/ai-logical-bug-scan` | `reports/ai_logic_scan_<timestamp>.md` + `.findings.json` |

These are plain markdown with tables, code blocks, and inline Mermaid
diagram source.  No PDF tooling, no PDF libraries, no PDF-related
skills exist in the runtime.

---

## Proposed Solution

### 1. Add an `/export-pdf` Command

A command that converts any existing markdown report to PDF:

```
/export-pdf extracted_code/appinfo_dll/reports/scan_appinfo_dll_20260309.md
/export-pdf appinfo.dll --latest scan
/export-pdf appinfo.dll --latest audit
```

Steps the command performs:
1. Locate the markdown report (by path or by `--latest <type>` lookup)
2. Parse into sections (headers, tables, code blocks, Mermaid blocks)
3. Render to PDF using reportlab Platypus (SimpleDocTemplate, Paragraph,
   Table, Spacer, Preformatted)
4. For Mermaid blocks: skip gracefully or render to SVG/PNG if `mmdc`
   is available
5. Save as `.pdf` alongside the original `.md` file

### 2. Install PDF Dependencies

The runtime currently has no `pyproject.toml` or `requirements.txt`.
PDF libraries need to be available in the Python environment:

**Required:**
- `reportlab>=4.0` -- PDF generation (Canvas + Platypus high-level API)
- `pypdf>=4.0` -- PDF reading, merging, splitting

**Optional (for advanced features):**
- `pdfplumber>=0.10` -- table extraction from existing PDFs
- `@mermaid-js/mermaid-cli` (npm) -- Mermaid diagram rendering to SVG

### 3. Create a PDF Export Script

Add a standalone script in `helpers/` or a new `pdf-export` skill:

```
.claude/skills/pdf-export/
  SKILL.md
  scripts/
    _common.py
    export_report.py      # markdown -> PDF conversion
    list_reports.py       # list available reports for a module
```

`export_report.py` accepts:
```
export_report.py <markdown_path> [--output <pdf_path>] [--json]
export_report.py --module <name> --latest <type> [--output <pdf_path>] [--json]
```

### Mermaid Diagram Handling

Mermaid blocks in markdown reports cannot be rendered to PDF directly.
Two strategies:

**Strategy A (graceful skip):** Replace Mermaid blocks with a
placeholder: `[Mermaid diagram -- view in markdown source]`.  This is
the default when `mmdc` is not installed.

**Strategy B (render if available):** If `@mermaid-js/mermaid-cli` is
installed (`npx mmdc --version` succeeds), render Mermaid source to
SVG, then embed in the PDF via reportlab's `svg2rlg` or PIL.

The command should detect which strategy to use automatically and log
which Mermaid blocks were skipped vs rendered.

---

## Architecture

### PDF Rendering Pipeline

```
Markdown report (.md)
  |
  v
Parse sections (headers, tables, code blocks, Mermaid blocks)
  |
  v
Map to reportlab Flowables:
  - Headers -> Paragraph with heading style
  - Tables  -> Table with alternating row colors
  - Code    -> Preformatted with monospace font
  - Mermaid -> SVG embed (if mmdc available) or placeholder
  |
  v
SimpleDocTemplate.build(flowables)
  |
  v
PDF output (.pdf) alongside the .md file
```

### Report Discovery

For `--latest <type>` mode, the script scans
`extracted_code/<module>/reports/` for files matching the pattern
`<type>_*_<timestamp>.md` and selects the most recent by timestamp.

---

## Integration Points

| Integration | File | Change |
|-------------|------|--------|
| Commands registry | `commands/registry.json` | Add `export-pdf` entry |
| Command definition | `commands/export-pdf.md` | New command with usage, steps, output |
| Skills registry | `skills/registry.json` | Add `pdf-export` entry (if skill-based) |
| Skill definition | `skills/pdf-export/SKILL.md` | Skill with YAML frontmatter |
| Script invocation guide | `rules/script-invocation-guide.mdc` | Add `export_report.py` signature |
| Commands README | `commands/README.md` | Add command entry |

### No Changes Needed To

- Existing report-generating commands -- they continue producing `.md`
- The `.findings.json` companion files -- PDF is for the `.md` only
- The workspace handoff pattern -- PDF export is a post-processing step

---

## What NOT to Build

- **No inline PDF generation in existing commands.** Commands like
  `/scan` and `/audit` should NOT gain a `--pdf` flag.  PDF export is
  a separate post-processing step via `/export-pdf`.  This keeps the
  report generation and rendering concerns separated.

- **No PDF reading/extraction capability.** The runtime analyzes
  Windows PE binaries, not PDF documents.  PDF reading (pdfplumber,
  OCR) is out of scope.

- **No custom PDF styling framework.** Use reportlab's built-in styles
  (Heading1-4, Normal, Code) with minimal customization.  The goal is
  readable output, not a branding exercise.

---

## Acceptance Criteria

1. `export_report.py <report.md>` produces a PDF with formatted text,
   tables, and code blocks
2. `export_report.py --module appinfo.dll --latest scan` finds and
   converts the most recent scan report
3. PDF output is saved alongside the source `.md` file (same directory,
   `.pdf` extension)
4. Mermaid blocks are skipped gracefully when `mmdc` is not available
5. Mermaid blocks are rendered to embedded SVG/PNG when `mmdc` is
   available
6. `/export-pdf` command is registered and documented
7. Code blocks in PDF use monospace font with syntax-aware formatting
8. Tables preserve column alignment and headers
9. No regression in existing report generation behavior

---

## References

- reportlab documentation: https://docs.reportlab.com/
- pypdf documentation: https://pypdf.readthedocs.io/
- Mermaid CLI: https://github.com/mermaid-js/mermaid-cli
- Current report paths: `extracted_code/<module>/reports/`
Anthropic SKill: https://github.com/anthropics/skills/tree/main/skills/pdf/scripts
