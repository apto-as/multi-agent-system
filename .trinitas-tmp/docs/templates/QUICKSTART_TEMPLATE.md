# Trinitas Quick Start Guide

**Time to first result**: 5 minutes

This guide will get you up and running with Trinitas in the fastest way possible.

---

## Prerequisites Check

Before starting, ensure you have:

- ✅ Claude Code or OpenCode installed
- ✅ Git installed
- ✅ Bash shell (built-in on macOS/Linux, use WSL on Windows)
- ✅ 5 minutes of time

**Not sure?** Run these commands:
```bash
git --version     # Should show: git version 2.x.x
bash --version    # Should show: GNU bash, version 5.x.x
```

---

## Installation (2 minutes)

### For Claude Code

```bash
# 1. Clone the repository
git clone https://github.com/apto-as/multi-agent-system.git
cd multi-agent-system

# 2. Run installer
chmod +x install-claude.sh
./install-claude.sh

# 3. Wait for completion (~2 minutes)
# ✅ Installing Trinitas agents...
# ✅ Configuring memory system...
# ✅ Setting up hooks...
# ✅ Installation complete!
```

### For OpenCode

```bash
# 1. Clone the repository
git clone https://github.com/apto-as/multi-agent-system.git
cd multi-agent-system

# 2. Run installer
chmod +x install-opencode.sh
./install-opencode.sh

# 3. Wait for completion (~2 minutes)
# ✅ Installing agents...
# ✅ Configuring plugins...
# ✅ Installation complete!
```

**Having issues?** See [Troubleshooting](#troubleshooting) below.

---

## Verification (1 minute)

Let's verify the installation works:

### Step 1: Start Claude

**Claude Code:**
```bash
claude
```

**OpenCode:**
```bash
opencode
```

### Step 2: Test a Simple Command

Type this in Claude:

```
Explain the Trinitas system
```

**Expected Response:**
```
Trinitas is a multi-agent AI system with six specialized personas:

1. Athena - Harmonious Conductor (architecture and planning)
2. Artemis - Technical Perfectionist (performance and quality)
3. Hestia - Security Guardian (security and auditing)
4. Eris - Tactical Coordinator (team coordination)
5. Hera - Strategic Commander (strategic planning)
6. Muses - Knowledge Architect (documentation)

Each persona brings unique expertise to create a comprehensive
development experience.
```

✅ **Success!** Trinitas is working.

---

## Your First Real Task (2 minutes)

Now let's try something practical.

### Example 1: Get Architecture Advice

```
Use Athena to design a REST API for a blog system with posts, comments, and users
```

**What happens:**
1. Athena analyzes the requirements
2. Provides architectural recommendations
3. Suggests database schema
4. Recommends API endpoints

### Example 2: Optimize Code

```
Artemis, optimize this code:

def find_duplicates(items):
    duplicates = []
    for i in range(len(items)):
        for j in range(i+1, len(items)):
            if items[i] == items[j] and items[i] not in duplicates:
                duplicates.append(items[i])
    return duplicates
```

**What happens:**
1. Artemis identifies O(n²) complexity
2. Suggests using a set for O(n) solution
3. Provides optimized code
4. Explains performance improvement

### Example 3: Security Audit

```
Hestia, audit this authentication code for security issues:

def login(username, password):
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    user = db.execute(query)
    return user
```

**What happens:**
1. Hestia identifies SQL injection vulnerability (CWE-89)
2. Flags plaintext password storage (CWE-256)
3. Provides secure implementation
4. Recommends additional security measures

---

## Understanding Persona Selection

Trinitas can select personas in two ways:

### 1. Automatic (Keywords)

Claude detects keywords and chooses the right persona:

| Your Request | Auto-Selected Persona | Why |
|--------------|----------------------|-----|
| "optimize this algorithm" | Artemis | Performance keyword |
| "design the architecture" | Athena | Architecture keyword |
| "audit for vulnerabilities" | Hestia | Security keyword |
| "document this API" | Muses | Documentation keyword |
| "coordinate the team" | Eris | Team/coordination keyword |
| "plan the roadmap" | Hera | Strategy/planning keyword |

### 2. Explicit (You Choose)

Specify which persona to use:

```
"Use [Persona] to [task]"
"Ask [Persona] about [topic]"
"Have [Persona] [action]"
```

Examples:
```
"Use Athena to explain microservices architecture"
"Ask Artemis about database indexing strategies"
"Have Hestia review this code for security issues"
```

---

## Multi-Agent Collaboration

For complex tasks, request multiple personas:

```
Analyze this authentication system from all perspectives
```

**Result:**
- **Athena**: Architecture analysis
- **Artemis**: Performance review
- **Hestia**: Security audit
- **Muses**: Documentation assessment

Each persona provides their expert perspective.

---

## Memory System Basics

Trinitas remembers context across sessions:

### Saving Information

```
Remember: We're using PostgreSQL for the database
```

### Recalling Information

```
What database are we using?
```

**Response:**
```
According to my memory, you're using PostgreSQL for the database.
```

**How it works:**
- Memories stored in `~/.claude/memory/` as plain text
- Automatically loaded in future sessions
- Transparent and editable

---

## Next Steps

Now that you're up and running:

### Learn More
- 📖 [User Guide](docs/user-guide/) - Comprehensive documentation
- 🎓 [Tutorials](docs/user-guide/tutorials/) - Step-by-step learning
- 💡 [Examples](examples/) - Real-world use cases

### Explore Personas
- 🏛️ [Athena](docs/user-guide/personas.md#athena) - Architecture and planning
- 🏹 [Artemis](docs/user-guide/personas.md#artemis) - Performance optimization
- 🔥 [Hestia](docs/user-guide/personas.md#hestia) - Security auditing
- ⚔️ [Eris](docs/user-guide/personas.md#eris) - Team coordination
- 🎭 [Hera](docs/user-guide/personas.md#hera) - Strategic planning
- 📚 [Muses](docs/user-guide/personas.md#muses) - Documentation

### Customize
- ⚙️ [Configuration](docs/reference/configuration.md) - Customize settings
- 🎨 [Customization Guide](docs/advanced/customization.md) - Advanced tweaks
- 🔌 [MCP Integration](docs/advanced/mcp-integration.md) - Connect tools

---

## Troubleshooting

### Installation fails with "Permission denied"

**Problem**: Script not executable

**Solution**:
```bash
chmod +x install-claude.sh
# or
chmod +x install-opencode.sh
```

### "Command not found: claude" or "Command not found: opencode"

**Problem**: Claude Code/OpenCode not in PATH

**Solution**:
- **Claude Code**: Reinstall or add to PATH
- **OpenCode**: Run `npm install -g opencode`

### Personas don't respond

**Problem**: Configuration not loaded

**Solution**:
1. Restart Claude
2. Check `~/.claude/` directory exists
3. Re-run installer

### Memory not working

**Problem**: Memory directory missing

**Solution**:
```bash
mkdir -p ~/.claude/memory/
```

**Still stuck?** See full [Troubleshooting Guide](docs/user-guide/troubleshooting.md)

---

## Common Commands

### Get Help

```
Explain how Trinitas works
What can Athena do?
Show me the available personas
```

### Coordination

```
Analyze [topic] from all perspectives
Have Athena and Artemis review [item]
Get security and performance assessment of [code]
```

### Memory

```
Remember: [information]
What did we decide about [topic]?
Recall our discussion about [subject]
```

---

## Tips for Success

### ✅ Do's

- **Be specific**: "Use Athena to design a REST API for a blog" ✅
- **Request collaboration**: "Analyze from all perspectives" ✅
- **Use memory**: "Remember: we use React for frontend" ✅
- **Explore personas**: Try different personas for different tasks ✅

### ❌ Don'ts

- **Too vague**: "Help me with code" ❌
- **Wrong persona**: Asking Muses to optimize performance ❌
- **Ignore security**: Not using Hestia for security-critical code ❌

---

## Quick Reference Card

```
┌─────────────────────────────────────────────────┐
│         Trinitas Quick Reference                │
├─────────────────────────────────────────────────┤
│ Installation                                    │
│ • Claude Code: ./install-claude.sh              │
│ • OpenCode: ./install-opencode.sh               │
├─────────────────────────────────────────────────┤
│ Personas                                        │
│ • Athena (🏛️): Architecture                     │
│ • Artemis (🏹): Performance                     │
│ • Hestia (🔥): Security                         │
│ • Eris (⚔️): Coordination                       │
│ • Hera (🎭): Strategy                           │
│ • Muses (📚): Documentation                     │
├─────────────────────────────────────────────────┤
│ Commands                                        │
│ • Use [Persona] to [task]                       │
│ • Analyze from all perspectives                 │
│ • Remember: [info]                              │
│ • What did we decide about [topic]?             │
├─────────────────────────────────────────────────┤
│ Files                                           │
│ • Config: ~/.claude/                            │
│ • Memory: ~/.claude/memory/                     │
│ • Agents: ~/.claude/agents/                     │
└─────────────────────────────────────────────────┘
```

---

## Getting Help

### Documentation
- 📖 [Full Documentation](docs/)
- ❓ [FAQ](docs/reference/faq.md)
- 🐛 [Troubleshooting](docs/user-guide/troubleshooting.md)

### Community
- 💬 [GitHub Discussions](https://github.com/apto-as/multi-agent-system/discussions)
- 🐛 [Report Issues](https://github.com/apto-as/multi-agent-system/issues)

### Contact
- 📧 Email: support@trinitas-project.example

---

## What's Next?

You're now ready to use Trinitas! Here are suggested learning paths:

### For New Users
1. Complete [Getting Started Tutorial](docs/user-guide/tutorials/01-getting-started.md) (10 min)
2. Try [Basic Examples](examples/basic-usage/) (15 min)
3. Read [Usage Patterns](docs/user-guide/usage-patterns.md) (20 min)

### For Developers
1. Read [Persona Deep Dive](docs/user-guide/personas.md) (30 min)
2. Try [API Development Example](examples/real-world/api-development/) (45 min)
3. Explore [Customization](docs/advanced/customization.md) (30 min)

### For Teams
1. Read [Team Coordination](docs/user-guide/usage-patterns.md#team-patterns) (20 min)
2. Review [Eris Examples](examples/basic-usage/02-multi-agent.md) (15 min)
3. Set up [Custom Workflows](docs/advanced/customization.md#workflows) (30 min)

---

**Congratulations!** You've completed the Trinitas Quick Start.

Ready to dive deeper? Start with the [User Guide](docs/user-guide/) →

---

*Trinitas v2.2.4 - Six Minds, Unified Intelligence*
