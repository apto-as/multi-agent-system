# Trinitas OpenCode Installation Guide

**Version**: 2.2.4
**Installation Method**: OpenCode Script with Plugin Support
**Target**: OpenCode users

## Overview

This installation method integrates Trinitas Agents with OpenCode through agent definitions and JavaScript plugins. OpenCode provides a plugin system similar to Claude Code's, allowing for dynamic context loading and agent-based workflows.

## Prerequisites

### Required Software

- **OpenCode** v0.14.1 or higher (v0.15.7 recommended)
- **Bash** shell (macOS/Linux/WSL)

### Verify Prerequisites

```bash
# Check OpenCode version
opencode --version
# Should show v0.14.1 or higher
```

### Installing OpenCode

If OpenCode is not installed:

- **npm**: `npm i -g opencode-ai@latest`
- **Homebrew**: `brew install sst/tap/opencode`

---

## Installation

### Quick Install

```bash
# Navigate to trinitas-agents directory
cd /path/to/trinitas-agents

# Run the installer
./install_opencode.sh

# Restart OpenCode (if running)
```

### What the Installer Does

1. **Checks prerequisites** - Verifies OpenCode CLI is available
2. **Backs up existing config** - Creates timestamped backup of `.opencode/`
3. **Installs agent definitions** - Copies 6 agent `.md` files
4. **Installs plugins** - Copies 4 JavaScript plugins
5. **Installs system instructions** - Copies `AGENTS.md`
6. **Verifies installation** - Counts installed components

### Installation Options

The installer provides two modes:

1. **Merge** - Keeps existing configuration, adds Trinitas
2. **Replace** - Clean install, removes existing `.opencode/`

---

## What Gets Installed

### Directory Structure

```
.opencode/
├── agent/                          # Agent Definitions (6 files)
│   ├── athena-conductor.md         # Strategic architect
│   ├── artemis-optimizer.md        # Performance expert
│   ├── hestia-auditor.md           # Security guardian
│   ├── eris-coordinator.md         # Team coordinator
│   ├── hera-strategist.md          # Strategic commander
│   └── muses-documenter.md         # Knowledge architect
│
├── plugin/                         # JavaScript Plugins (4 files)
│   ├── dynamic-context-loader.js   # Context detection
│   ├── narrative-engine.js         # Persona narratives
│   ├── performance-monitor.js      # Performance tracking
│   └── quality-enforcer.js         # Code quality
│
├── AGENTS.md                       # System instructions
│
└── (optional) docs/                # Additional documentation
```

### Component Details

#### Agent Definitions (6)

Markdown files that define each agent's personality, capabilities, and operational guidelines:

- **Athena** - System architecture and strategic coordination
- **Artemis** - Technical optimization and code quality
- **Hestia** - Security analysis and risk assessment
- **Eris** - Tactical coordination and conflict resolution
- **Hera** - Strategic planning and orchestration
- **Muses** - Documentation and knowledge management

#### JavaScript Plugins (4)

**1. dynamic-context-loader.js** (7.4KB)
- Detects user intent from keywords
- Suggests relevant context files
- Triggers: `tmws`, `security`, `performance`, `coordination`

**2. narrative-engine.js** (11KB)
- Persona-based narrative generation
- Adapts tone based on active agent
- Supports 6 Trinitas personas

**3. performance-monitor.js** (4.1KB)
- Tracks response times
- Monitors token usage
- Reports performance metrics

**4. quality-enforcer.js** (5.1KB)
- Enforces code quality standards
- Linting rule suggestions
- Best practice recommendations

---

## Usage

### Starting OpenCode with Trinitas

```bash
# Default agent (general)
opencode

# Start with specific agent
opencode --agent athena

# Other agent options
opencode --agent artemis    # Performance optimization
opencode --agent hestia     # Security focus
opencode --agent eris       # Team coordination
opencode --agent hera       # Strategic planning
opencode --agent muses      # Documentation
```

### Switching Agents

While OpenCode is running:

1. Press **Tab** key to open agent selector
2. Choose from 6 Trinitas agents
3. Agent context loads automatically

### Using Agent Commands

Once an agent is active, you can:

```
# Execute task with current agent
"Optimize this database query"  (with artemis active)

# Request specific agent
"Have athena analyze this architecture"

# Parallel analysis
"Analyze this code with artemis and hestia"
```

### Plugin Behavior

Plugins activate automatically on:

- **session.start** - When OpenCode starts
- **session.idle** - After 5 minutes of inactivity
- **tool.execute.before** - Before any tool execution

Example plugin triggers:

```
User: "How can I improve security?"
→ dynamic-context-loader detects "security" keyword
→ Suggests hestia agent
→ narrative-engine adjusts tone to security-focused

User: "Optimize this function"
→ dynamic-context-loader detects "optimize"
→ Suggests artemis agent
→ performance-monitor starts tracking
```

---

## Trinitas Agents

### Available Agents

| Agent | Role | When to Use |
|-------|------|------------|
| **athena** | Harmonious Conductor | System design, architecture planning |
| **artemis** | Technical Perfectionist | Performance optimization, code quality |
| **hestia** | Security Guardian | Security audits, risk assessment |
| **eris** | Tactical Coordinator | Team coordination, conflict resolution |
| **hera** | Strategic Commander | Strategic planning, project management |
| **muses** | Knowledge Architect | Documentation, knowledge organization |

### Agent Selection Examples

**Architecture Design**:
```bash
opencode --agent athena
> "Design a microservices architecture for our e-commerce platform"
```

**Performance Optimization**:
```bash
opencode --agent artemis
> "Profile this code and suggest optimizations"
```

**Security Audit**:
```bash
opencode --agent hestia
> "Review this authentication system for vulnerabilities"
```

**Team Coordination**:
```bash
opencode --agent eris
> "Help coordinate tasks between frontend and backend teams"
```

**Strategic Planning**:
```bash
opencode --agent hera
> "Create a 6-month roadmap for this project"
```

**Documentation**:
```bash
opencode --agent muses
> "Generate comprehensive API documentation"
```

---

## Plugin Development

### OpenCode Plugin API

Trinitas plugins use the OpenCode plugin format:

```javascript
export const MyPlugin = async ({ project, client, $, directory, worktree }) => {
  return {
    // Session lifecycle events
    event: async ({ event }) => {
      if (event.type === "session.start") {
        // On OpenCode startup
      }
    },

    // Custom tools
    tool: {
      my_tool: tool({
        description: "Tool description",
        args: { /* ... */ },
        async execute({ arg1, arg2 }) {
          // Tool implementation
        }
      })
    },

    // Tool execution hooks
    "tool.execute.before": async (input, output) => {
      // Before any tool executes
    }
  };
};
```

### Adding Custom Plugins

1. **Create plugin file**:
   ```javascript
   // .opencode/plugin/my-plugin.js
   export const MyPlugin = async ({ project, client, $ }) => {
     // Your plugin logic
   };
   ```

2. **Restart OpenCode**:
   ```bash
   opencode
   # Plugin loads automatically
   ```

---

## Configuration

### Customizing Agent Definitions

Agent definitions are in `.opencode/agent/*.md`:

```bash
# Edit agent definition
nano .opencode/agent/artemis-optimizer.md

# Add custom instructions
# Restart OpenCode to apply
```

### Customizing System Instructions

```bash
# Edit global system instructions
nano .opencode/AGENTS.md

# Restart OpenCode
```

### Plugin Configuration

Some plugins support configuration via `.opencode/config/`:

```javascript
// .opencode/config/narratives.json
{
  "athena": {
    "tone": "harmonious",
    "style": "collaborative"
  }
}
```

---

## Troubleshooting

### Agents not showing up

**Problem**: Agent definitions not loaded

**Solutions**:
1. Verify files exist:
   ```bash
   ls -la .opencode/agent/*.md
   # Should show 6 .md files
   ```

2. Restart OpenCode:
   ```bash
   # Kill any running instance
   pkill opencode

   # Start fresh
   opencode
   ```

3. Check for errors:
   ```bash
   opencode 2>&1 | grep -i error
   ```

### Plugins not loading

**Problem**: JavaScript plugin errors

**Solutions**:
1. Verify plugins exist:
   ```bash
   ls -la .opencode/plugin/*.js
   # Should show 4 .js files
   ```

2. Check plugin syntax:
   ```bash
   # Test plugin manually
   node .opencode/plugin/dynamic-context-loader.js
   ```

3. Review OpenCode console output for errors

### "OpenCode command not found"

**Problem**: OpenCode not installed or not in PATH

**Solutions**:
```bash
# Install via npm
npm i -g opencode-ai@latest

# Or via Homebrew
brew install sst/tap/opencode

# Verify installation
which opencode
opencode --version
```

### Performance issues with plugins

**Problem**: Plugins slowing down OpenCode

**Solutions**:
1. **Temporarily disable plugins**:
   ```bash
   mv .opencode/plugin .opencode/plugin.disabled
   opencode
   ```

2. **Re-enable one by one** to identify problematic plugin

3. **Optimize plugin code** or remove heavy operations

---

## Updating

### Updating Trinitas

```bash
# Navigate to trinitas-agents directory
cd /path/to/trinitas-agents

# Pull latest changes
git pull origin main

# Re-run installer
./install_opencode.sh

# Choose "Merge" to keep existing config
# Or "Replace" for clean install
```

### Updating OpenCode

```bash
# Update via npm
npm update -g opencode-ai

# Or via Homebrew
brew upgrade opencode
```

---

## Uninstallation

### Remove Trinitas from OpenCode

```bash
# Remove agent definitions
rm .opencode/agent/athena-conductor.md
rm .opencode/agent/artemis-optimizer.md
rm .opencode/agent/hestia-auditor.md
rm .opencode/agent/eris-coordinator.md
rm .opencode/agent/hera-strategist.md
rm .opencode/agent/muses-documenter.md

# Remove plugins
rm .opencode/plugin/dynamic-context-loader.js
rm .opencode/plugin/narrative-engine.js
rm .opencode/plugin/performance-monitor.js
rm .opencode/plugin/quality-enforcer.js

# Remove system instructions
rm .opencode/AGENTS.md

# Restart OpenCode
```

### Complete Removal

```bash
# Remove entire .opencode directory
rm -rf .opencode/

# Restart OpenCode (will create fresh .opencode/)
```

---

## Comparison with Claude Code Installation

| Feature | OpenCode Script | Claude Code Plugin |
|---------|---------------|-------------------|
| Agent Definitions | ✓ 6 MD files | ✓ MCP resources |
| Plugin System | ✓ JavaScript | ✓ MCP tools |
| Context Loading | ✓ Dynamic | ✓ On-demand |
| Setup Time | 3 minutes | 5 minutes |
| Prerequisites | OpenCode | Node.js 18+, Claude Desktop |
| Memory System | File-based | MCP-based |
| Custom Tools | Via plugins | Via MCP tools |

---

## Advanced Usage

### Combining Agents

Request multiple agents for complex analysis:

```
"Analyze this system with athena (architecture),
artemis (performance), and hestia (security)"
```

OpenCode will sequentially or parallelly engage the specified agents.

### Context Customization

Create custom context files in `.opencode/`:

```markdown
# .opencode/my-context.md

# Custom Context

This context is loaded when...
```

Reference in agent definitions or request directly:

```
"Use my-context.md to analyze this code"
```

---

## Plugin Reference

### dynamic-context-loader.js

**Triggers**:
- Keywords: `tmws`, `memory`, `workflow`, `security`, `performance`, `coordinate`
- Threshold: 1-2 keyword matches

**Actions**:
- Suggests relevant agent
- Loads context files
- Updates UI with suggestions

### narrative-engine.js

**Personas**: athena, artemis, hestia, eris, hera, muses

**Behavior**:
- Adapts response tone
- Uses persona-specific language patterns
- Maintains character consistency

### performance-monitor.js

**Metrics**:
- Response time
- Token usage
- Tool execution time

**Output**: Logged to console, available for analysis

### quality-enforcer.js

**Checks**:
- Code style consistency
- Security best practices
- Performance anti-patterns

**Output**: Inline suggestions and warnings

---

## Support

For issues or questions:

1. Check [troubleshooting section](#troubleshooting)
2. Review OpenCode console output
3. Verify all prerequisites are met
4. Test plugins individually

---

## Version History

- **v2.2.4** - Added full plugin support (4 plugins)
- **v2.2.3** - Initial OpenCode integration
- **v2.2.0** - Agent definitions only

---

## License

Part of Trinitas Agents system. See main project LICENSE for details.
