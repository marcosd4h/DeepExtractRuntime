# Brainstorming -- Reference

## Contents

- [Question Frameworks](#question-frameworks)
- [VR Campaign Planning Template](#vr-campaign-planning-template)
- [Design Presentation Patterns](#design-presentation-patterns)
- [Trade-off Analysis Template](#trade-off-analysis-template)

## Question Frameworks

### VR Research Planning

Ask these questions to scope a vulnerability research campaign:

1. **Target**: Which module, component, or function class?
2. **Hypothesis**: What vulnerability class are you looking for?
   - Memory corruption (buffer overflow, use-after-free, integer overflow)
   - Logic bugs (auth bypass, TOCTOU, privilege escalation)
   - Type confusion (COM interface casting, variant handling)
   - Race conditions (file operations, registry access, token manipulation)
3. **Threat model**: What's the attacker's starting position?
   - Local unprivileged user, medium IL process, AppContainer
   - Remote network attacker, authenticated/unauthenticated
   - Adjacent (same machine, different security context)
4. **Scope**: How deep vs. how broad?
   - Deep single-function audit (1 function, full decompiler verification)
   - Targeted pattern scan (10-50 functions matching a pattern)
   - Broad module triage (all functions, classification + ranking)
5. **Prior work**: What analysis has already been done?
   - Check cached results: `/cache-manage stats`
   - Check workspace runs: `.agent/workspace/`

### Tool/Skill Design

1. **Purpose**: What problem does this solve? (one sentence)
2. **Users**: Who will use it? (agent, researcher, both)
3. **Input/output**: What goes in, what comes out?
4. **Integration**: Which existing skills/helpers does it build on?
5. **Success criteria**: How will we know it works?

## VR Campaign Planning Template

```markdown
# VR Campaign: [Target Module]

## Hypothesis
[Vulnerability class] in [component/function class] because [reasoning]

## Attack Surface
- Entry points: [from /triage or map-attack-surface]
- Trust boundaries: [caller privilege vs. callee privilege]
- Attacker-controlled inputs: [parameters, file contents, registry values]

## Research Plan
1. Triage: /triage <module>
2. Focus: [specific functions or patterns to investigate]
3. Deep analysis: [/audit, /taint, /trace-export on selected targets]
4. Verification: [/verify on findings to confirm decompiler accuracy]

## Expected Findings
- [What you expect to find and why]

## Exit Criteria
- [When to stop: N functions audited, all exports traced, etc.]
```

## Design Presentation Patterns

### Simple Decision (1 section)

Good for: binary choices, flag additions, small config changes.

```
Here's what I'd recommend: [option].

Reason: [brief justification].

Alternative: [other option] -- [why it's worse].

Shall I proceed?
```

### Moderate Design (2-3 sections)

Good for: new scripts, skill enhancements, command modifications.

```
## Approach
[What we'll build and why]

## Key Decisions
1. [Decision 1]: [chosen option] because [reason]
2. [Decision 2]: [chosen option] because [reason]

## Implementation Steps
1. [Step 1]
2. [Step 2]
3. [Step 3]

Does this look right? Any concerns before I proceed?
```

### Complex Design (incremental)

Good for: new skills, architectural changes, multi-agent workflows.

Present one section at a time. Check for agreement before continuing.

```
Let me walk through this in parts.

## Part 1: [First Major Component]
[Description]

Does this direction make sense? [wait for response]

## Part 2: [Second Major Component]
[Description, building on Part 1]

Any adjustments? [wait for response]

## Part 3: [Integration]
[How parts connect]
```

## Trade-off Analysis Template

```markdown
| Dimension | Option A | Option B | Option C |
|-----------|----------|----------|----------|
| Complexity | Low | Medium | High |
| Coverage | Narrow | Moderate | Broad |
| Speed | Fast | Medium | Slow |
| Maintenance | Easy | Medium | Hard |
| Risk | Low | Medium | High |

**Recommendation**: Option B because [it balances coverage and complexity].
```
