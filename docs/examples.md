# Examples

## Interactive Commands

```text
/triage appinfo.dll
/audit appinfo.dll AiLaunchProcess
/explain appinfo.dll AiCheckSecureApplicationDirectory
/verify appinfo.dll AiLaunchProcess
/scan appinfo.dll --top 15
/compare-modules appinfo.dll consent.exe
/health
```

## Batch Pipeline CLI

```bash
python .agent/helpers/pipeline_cli.py list-steps
python .agent/helpers/pipeline_cli.py validate config/pipelines/security-sweep.yaml
python .agent/helpers/pipeline_cli.py run config/pipelines/security-sweep.yaml --dry-run
python .agent/helpers/pipeline_cli.py run config/pipelines/quick-triage.yaml --json
python .agent/helpers/pipeline_cli.py run config/pipelines/security-sweep.yaml --modules appinfo.dll,consent.exe
python .agent/helpers/pipeline_cli.py run config/pipelines/full-analysis.yaml --output workspace/custom_{timestamp}/
```

For interactive use, the `/pipeline` slash command wraps the same CLI.

## Example YAML Snippets

Minimal:

```yaml
modules: all
steps:
  - triage: {}
```

Focused security sweep:

```yaml
modules:
  - appinfo.dll
  - consent.exe
steps:
  - triage: {}
  - security:
      top: 10
  - scan:
      top: 10
```
