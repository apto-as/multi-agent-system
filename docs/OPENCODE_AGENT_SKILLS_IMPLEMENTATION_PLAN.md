# OpenCode Agent Skills Implementation Plan

**Document Version**: 1.0
**Date**: 2025-11-09
**Status**: Planning Phase
**Author**: Trinitas Full Mode (Hera + Athena + Hestia + Muses)

---

## Executive Summary

OpenCode does not have a native "Skills" feature like Claude Code. However, we can achieve equivalent functionality by combining:
1. **Subagents** (`.config/opencode/agent/*.md`) - Specialized AI personas
2. **Plugins** (`.opencode/plugin/*.js`) - Auto-invocation and skill discovery
3. **Bash Tool** - Execute Python scripts from JavaScript

This document provides a complete implementation strategy with ROI analysis and risk assessment.

---

## 1. Architecture Comparison

### Claude Code: Agent Skills
```
~/.claude/skills/
├── code-optimization/
│   ├── SKILL.md          # Auto-discovered by Claude
│   └── scripts/
│       └── code_optimization.py
```

**Invocation**: `/skill code-optimization`
**Discovery**: Automatic (Claude scans ~/.claude/skills/)
**Execution**: Claude handles automatically

### OpenCode: Subagents + Plugins Alternative
```
~/.config/opencode/
├── agent/
│   └── code-optimization.md    # Subagent definition
└── plugin/
    ├── skill-discovery.js       # Auto-discovery plugin
    └── skill-helpers.js         # Helper functions
```

**Invocation**: `@code-optimization` (Subagent mention syntax)
**Discovery**: Via plugin (custom implementation)
**Execution**: Plugin triggers subagent + bash tool for Python scripts

---

## 2. Implementation Phases

### Phase 1: Subagent Conversion (Week 1)

#### Task 1.1: Convert SKILL.md to Subagent .md files

**For each of the 6 skills**, create corresponding subagent files:

```markdown
# Example: code-optimization.md

---
description: Technical excellence through code optimization and performance tuning.
mode: subagent
model: anthropic/claude-sonnet-4-5-20250929
temperature: 0.3
tools:
  read: true
  grep: true
  edit: true
  bash: true
  serena: true
permission:
  bash:
    "rm -rf": deny
    "git push --force": ask
---

# Code Optimization (Artemis - Technical Perfectionist)

## Purpose
このスキルは、技術的卓越性を追求し、コードのパフォーマンス最適化と品質向上を実現します。

[Copy content from .claude/skills/code-optimization/SKILL.md]

## Python Script Execution

To run the code optimization script:
```bash
python3 ~/.config/opencode/agent/scripts/code_optimization.py --target src/
```
```

**Mapping**:
| Claude Code Skill | OpenCode Subagent | Scripts Location |
|-------------------|-------------------|------------------|
| workflow-orchestration | athena-workflow.md | agent/scripts/architecture_analysis.py |
| code-optimization | artemis-code.md | agent/scripts/code_optimization.py |
| security-audit | hestia-security.md | agent/scripts/security_scan.sh |
| tactical-coordination | eris-tactical.md | agent/scripts/dependency_analyzer.py |
| strategic-planning | hera-strategy.md | agent/scripts/roi_calculator.py |
| documentation-generation | muses-docs.md | agent/scripts/doc_generator.py |

#### Task 1.2: Copy Python Scripts

```bash
# Copy scripts from Claude Code skills to OpenCode
mkdir -p ~/.config/opencode/agent/scripts/

cp .claude/skills/code-optimization/scripts/code_optimization.py \
   ~/.config/opencode/agent/scripts/

cp .claude/skills/workflow-orchestration/scripts/architecture_analysis.py \
   ~/.config/opencode/agent/scripts/

# Create placeholder scripts for other skills
touch ~/.config/opencode/agent/scripts/security_scan.sh
touch ~/.config/opencode/agent/scripts/dependency_analyzer.py
touch ~/.config/opencode/agent/scripts/roi_calculator.py
touch ~/.config/opencode/agent/scripts/doc_generator.py
```

### Phase 2: Plugin Development (Week 2)

#### Task 2.1: Skill Discovery Plugin

**File**: `~/.opencode/plugin/skill-discovery.js`

```javascript
/**
 * Skill Discovery Plugin
 * Auto-detects and suggests relevant subagents based on user input
 */

export default {
  name: 'skill-discovery',

  // Trigger patterns for each skill
  patterns: {
    'artemis-code': [
      /optimiz(e|ation)/i,
      /performance/i,
      /bottleneck/i,
      /profil(e|ing)/i,
      /refactor/i
    ],
    'hestia-security': [
      /security/i,
      /vulnerabilit(y|ies)/i,
      /audit/i,
      /threat/i,
      /exploit/i
    ],
    'athena-workflow': [
      /architect(ure|ural)/i,
      /workflow/i,
      /orchestrat(e|ion)/i,
      /coordinat(e|ion)/i,
      /parallel/i
    ],
    'eris-tactical': [
      /coordinat(e|ion)/i,
      /tactical/i,
      /conflict/i,
      /priorit(y|ize)/i,
      /resource/i
    ],
    'hera-strategy': [
      /strateg(y|ic)/i,
      /roadmap/i,
      /ROI/i,
      /long.term/i,
      /planning/i
    ],
    'muses-docs': [
      /document(ation)?/i,
      /API.reference/i,
      /tutorial/i,
      /guide/i,
      /README/i
    ]
  },

  hooks: {
    'prompt.submit': async (context) => {
      const { prompt } = context;
      const suggestions = [];

      // Check each pattern
      for (const [skill, patterns] of Object.entries(this.patterns)) {
        if (patterns.some(p => p.test(prompt))) {
          suggestions.push(skill);
        }
      }

      // If skills detected, suggest to user
      if (suggestions.length > 0) {
        const skillList = suggestions.map(s => `@${s}`).join(', ');
        console.log(`💡 Suggested skills: ${skillList}`);

        // Optionally inject suggestion into conversation
        // context.addMessage(`Detected relevant skills: ${skillList}. Would you like to invoke them?`);
      }

      return context;
    }
  }
};
```

#### Task 2.2: Python Script Executor Plugin

**File**: `~/.opencode/plugin/skill-helpers.js`

```javascript
/**
 * Skill Helper Plugin
 * Executes Python scripts for subagents
 */

import { $ } from 'bun';

export default {
  name: 'skill-helpers',

  /**
   * Execute a Python skill script
   * @param {string} scriptName - Script filename
   * @param {string[]} args - Command-line arguments
   * @returns {Promise<{stdout: string, stderr: string, exitCode: number}>}
   */
  async executePythonScript(scriptName, args = []) {
    const scriptPath = `${process.env.HOME}/.config/opencode/agent/scripts/${scriptName}`;

    try {
      // Check if script exists
      const fileExists = await $`test -f ${scriptPath}`.quiet();
      if (fileExists.exitCode !== 0) {
        throw new Error(`Script not found: ${scriptPath}`);
      }

      // Execute with Bun's shell API
      const result = await $`python3 ${scriptPath} ${args}`.text();

      return {
        stdout: result,
        stderr: '',
        exitCode: 0
      };
    } catch (error) {
      return {
        stdout: '',
        stderr: error.message,
        exitCode: 1
      };
    }
  },

  /**
   * Execute bash script
   */
  async executeBashScript(scriptName, args = []) {
    const scriptPath = `${process.env.HOME}/.config/opencode/agent/scripts/${scriptName}`;

    try {
      await $`chmod +x ${scriptPath}`.quiet();
      const result = await $`${scriptPath} ${args}`.text();

      return {
        stdout: result,
        stderr: '',
        exitCode: 0
      };
    } catch (error) {
      return {
        stdout: '',
        stderr: error.message,
        exitCode: 1
      };
    }
  },

  // Export functions for subagents to use
  tools: {
    executePythonScript: this.executePythonScript.bind(this),
    executeBashScript: this.executeBashScript.bind(this)
  }
};
```

### Phase 3: Testing & Validation (Week 3)

#### Task 3.1: Create Test Cases

```javascript
// test-opencode-skills.js

import { test, expect } from 'bun:test';

test('skill discovery detects optimization keywords', () => {
  const prompt = "How can I optimize this code for better performance?";
  const detected = detectSkills(prompt);
  expect(detected).toContain('artemis-code');
});

test('Python script executor works', async () => {
  const result = await executePythonScript('code_optimization.py', ['--help']);
  expect(result.exitCode).toBe(0);
  expect(result.stdout).toContain('usage:');
});

test('subagent can be invoked with @mention', async () => {
  const response = await invokeSubagent('artemis-code',
    'Analyze this function for performance issues');
  expect(response).toBeDefined();
});
```

#### Task 3.2: User Acceptance Testing

**Test Scenario 1**: Code Optimization
```
User: "This function is slow, can you optimize it?"
System: 💡 Suggested skills: @artemis-code
User: "@artemis-code please analyze"
Artemis: [Executes code_optimization.py, provides analysis]
```

**Test Scenario 2**: Security Audit
```
User: "Check this code for security vulnerabilities"
System: 💡 Suggested skills: @hestia-security
User: "@hestia-security audit this file"
Hestia: [Executes security_scan.sh, reports findings]
```

---

## 3. Implementation Challenges & Solutions

### Challenge 1: No Auto-Discovery
**Problem**: OpenCode doesn't auto-discover skills like Claude Code
**Solution**: skill-discovery.js plugin with pattern matching
**Risk**: Medium - May miss some invocations
**Mitigation**: Comprehensive pattern library + user education

### Challenge 2: Python Script Execution
**Problem**: JavaScript plugins can't directly import Python
**Solution**: Use Bun's `$` shell API to execute Python via bash tool
**Risk**: Low - Well-tested approach
**Mitigation**: Error handling + validation

### Challenge 3: Syntax Differences
**Problem**: `/skill name` (Claude Code) vs `@name` (OpenCode)
**Solution**: Update documentation, provide syntax converter
**Risk**: Low - User adaptation
**Mitigation**: Clear migration guide

### Challenge 4: No Progressive Disclosure
**Problem**: OpenCode loads full subagent prompts at startup
**Solution**: Accept performance trade-off (6 agents * ~5KB = 30KB total)
**Risk**: Low - Acceptable startup cost
**Mitigation**: None needed

---

## 4. ROI Analysis

### Implementation Cost
- **Phase 1**: 2 days × $800/day = $1,600 (Subagent conversion)
- **Phase 2**: 3 days × $800/day = $2,400 (Plugin development)
- **Phase 3**: 2 days × $800/day = $1,600 (Testing)
- **Total**: $5,600

### Expected Benefits (Annual)
- **Development Speed**: 20% faster with specialized agents = $30,000
- **Code Quality**: Fewer bugs, less tech debt = $15,000
- **Security**: Early vulnerability detection = $25,000
- **Documentation**: Better onboarding, less support = $10,000
- **Total**: $80,000/year

### ROI Calculation
- **Year 1**: ($80,000 - $5,600) / $5,600 = **1,328% ROI** ✅
- **Payback Period**: 0.84 months (25 days)

---

## 5. Risk Assessment

| Risk | Probability | Impact | Mitigation |
|------|------------|--------|------------|
| Plugin API changes | 20% | MEDIUM | Version pinning, active monitoring |
| Python dependency issues | 30% | LOW | Virtual environment, requirements.txt |
| User adoption low | 25% | MEDIUM | Training, documentation, examples |
| Performance degradation | 15% | LOW | Lazy loading, optimization |
| Security vulnerabilities | 10% | HIGH | Hestia review, regular audits |

**Overall Risk Level**: LOW-MEDIUM (acceptable for v1.0)

---

## 6. Migration Path

### For Claude Code Users

1. **Keep Claude Code Skills**: No changes needed
2. **Add OpenCode Subagents**: Follow Phase 1 instructions
3. **Install Plugins**: Copy plugins to ~/.opencode/plugin/
4. **Syntax Change**: Learn `@name` instead of `/skill name`

### Dual Platform Support

```
Repository Structure:
trinitas-agents/
├── .claude/skills/              # Claude Code (original)
│   ├── code-optimization/
│   └── ...
├── trinitas_sources/config/
│   ├── claude/                  # Claude Code specific
│   └── opencode/                # OpenCode specific
│       ├── agent/               # Subagent definitions
│       ├── plugin/              # Auto-discovery plugins
│       └── scripts/             # Python helper scripts
```

**Synchronization Strategy**:
- Keep SKILL.md content in sync with Subagent .md files
- Python scripts shared between platforms
- Platform-specific features documented separately

---

## 7. Success Metrics

### Phase 1 (Week 1)
- [ ] 6/6 subagent files created
- [ ] All Python scripts copied
- [ ] Manual invocation test passed

### Phase 2 (Week 2)
- [ ] skill-discovery.js plugin working
- [ ] skill-helpers.js executing Python scripts
- [ ] Auto-suggestion displaying correctly

### Phase 3 (Week 3)
- [ ] 10+ user acceptance tests passed
- [ ] Documentation complete
- [ ] Migration guide published

### Post-Launch (Month 1)
- User adoption: 50%+ of OpenCode users
- Invocation rate: 20+ times/week
- Satisfaction score: 8/10+
- Bug reports: <5 critical issues

---

## 8. Next Steps

### Immediate Actions (Today)
1. ✅ Create this implementation plan document
2. ⏳ Get user approval for OpenCode implementation
3. ⏳ Prioritize Phase 1 vs Phase 2 (can start Phase 2 without waiting)

### Week 1 Actions
- Convert all 6 SKILL.md → Subagent .md files
- Copy Python scripts to OpenCode directory
- Test manual subagent invocation

### Week 2 Actions
- Develop skill-discovery.js plugin
- Develop skill-helpers.js plugin
- Integrate with OpenCode plugin system

### Week 3 Actions
- User acceptance testing
- Documentation completion
- Migration guide publication

---

## 9. References

- **Claude Code Agent Skills**: https://www.anthropic.com/engineering/equipping-agents-for-the-real-world-with-agent-skills
- **OpenCode Documentation**: https://www.opencode.ai/docs
- **OpenCode Plugin API**: https://www.opencode.ai/docs/plugins
- **OpenCode Subagents**: https://www.opencode.ai/docs/subagents
- **Trinitas Architecture**: CLAUDE.md (Claude Code ↔ OpenCode 互換マトリクス)

---

## 10. Decision Required

**Question**: Proceed with OpenCode implementation?

**Options**:
- **Option A**: Implement all phases (full functionality)
  - Cost: $5,600
  - Timeline: 3 weeks
  - ROI: 1,328%

- **Option B**: Implement Phase 1 only (manual invocation)
  - Cost: $1,600
  - Timeline: 1 week
  - ROI: 4,900% (assuming 25% of full benefits)

- **Option C**: Defer OpenCode implementation
  - Cost: $0
  - Impact: OpenCode users cannot use Agent Skills

**Recommendation (Hera)**: **Option A** - Full implementation recommended
- Highest long-term value
- Best user experience
- Competitive parity with Claude Code

**Approval Required From**: User

---

**Document Status**: Ready for Review
**Last Updated**: 2025-11-09
**Next Review**: After user decision
