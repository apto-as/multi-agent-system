# Trinitas - Multi-Agent AI Development System

![Build Status](https://img.shields.io/github/actions/workflow/status/apto-as/multi-agent-system/ci.yml?branch=main)
![Version](https://img.shields.io/badge/version-2.2.4-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Claude%20Code%20%7C%20OpenCode-purple)

> **Six specialized AI personas working together for optimal software development**

Trinitas is an advanced multi-agent AI system featuring six personas based on Greek/Roman mythology. Each persona brings unique expertise to create a comprehensive development experience that combines strategic planning, technical excellence, and security-first design.

---

## ✨ What Makes Trinitas Different?

- **🏛️ Six Specialized Personas** - Each with domain expertise (architecture, performance, security, coordination, strategy, documentation)
- **🤝 Seamless Coordination** - Agents automatically collaborate on complex tasks
- **🛡️ Security Built-In** - Hestia ensures safe operations with real-time auditing
- **📖 Self-Documenting** - Muses automatically records decisions and patterns
- **⚡ Performance Optimized** - Artemis continuously monitors and improves efficiency
- **🎯 Strategic Guidance** - Athena and Hera provide long-term vision and planning

---

## 🚀 Quick Start

### 5-Minute Installation

**For Claude Code:**
```bash
git clone https://github.com/apto-as/multi-agent-system.git
cd multi-agent-system
./install-claude.sh
```

**For OpenCode:**
```bash
git clone https://github.com/apto-as/multi-agent-system.git
cd multi-agent-system
./install-opencode.sh
```

**Verify Installation:**
```bash
# Ask Claude:
"Use Athena to explain the Trinitas system"
```

Full installation guides: [INSTALLATION.md](INSTALLATION.md)

---

## 👥 Meet the Personas

| Persona | Icon | Expertise | When to Use |
|---------|------|-----------|-------------|
| **Athena** | 🏛️ | System Architecture & Strategic Design | Planning, orchestration, high-level design |
| **Artemis** | 🏹 | Performance & Code Quality | Optimization, refactoring, technical excellence |
| **Hestia** | 🔥 | Security & Risk Management | Auditing, vulnerability assessment, compliance |
| **Eris** | ⚔️ | Team Coordination & Workflow | Process improvement, conflict resolution, coordination |
| **Hera** | 🎭 | Strategic Planning & Orchestration | Roadmaps, long-term planning, stakeholder management |
| **Muses** | 📚 | Documentation & Knowledge | Technical writing, API docs, knowledge management |

**Learn more**: [docs/user-guide/personas.md](docs/user-guide/personas.md)

---

## 💡 Usage Examples

### Example 1: Single Agent Task

```
User: "Artemis, optimize this database query"

SELECT * FROM users
WHERE created_at > '2024-01-01'
ORDER BY created_at DESC;

Artemis: "I'll optimize this query for performance:

1. Add index on created_at column
2. Select only needed columns (avoid SELECT *)
3. Use pagination to limit result set

Optimized:
CREATE INDEX idx_users_created_at ON users(created_at DESC);

SELECT id, name, email, created_at
FROM users
WHERE created_at > '2024-01-01'
ORDER BY created_at DESC
LIMIT 100;

Performance gain: ~85% faster on tables with 1M+ rows"
```

### Example 2: Multi-Agent Collaboration

```
User: "Analyze this authentication system from all perspectives"

Athena: "Architecture review - System uses JWT with refresh tokens.
Recommendations:
1. Add token rotation for enhanced security
2. Implement centralized token management
3. Consider session management for scalability"

Artemis: "Performance analysis - Current implementation:
Issues:
1. Database hit on every token validation (N+1)
2. No caching for user roles
Solutions:
1. Implement Redis cache for token validation
2. Cache user permissions with 5-minute TTL
Expected: 70% reduction in auth overhead"

Hestia: "Security audit - Critical findings:
⚠️ HIGH: No rate limiting on login endpoint (CWE-770)
⚠️ MEDIUM: JWT secret stored in code (CWE-798)
⚠️ LOW: Password minimum length is 6 (recommend 12+)
Mitigation plan:
1. Add rate limiting: 5 attempts per 15 minutes
2. Move JWT secret to environment variable
3. Increase password requirements"

Muses: "Documentation gaps identified:
1. No API authentication flow diagram
2. Missing token refresh endpoint documentation
3. No security best practices guide
I'll create comprehensive authentication documentation."
```

### Example 3: Strategic Planning

```
User: "Hera, create a roadmap for migrating to microservices"

Hera: "Strategic migration roadmap - 18-month plan:

Phase 1: Foundation (Months 1-3)
- Containerize monolith
- Implement API gateway
- Set up service mesh infrastructure
- Risk: Medium | Priority: Critical

Phase 2: Extract Services (Months 4-9)
- Extract authentication service
- Extract payment processing
- Implement event-driven communication
- Risk: High | Priority: High

Phase 3: Scale & Optimize (Months 10-15)
- Implement auto-scaling
- Add circuit breakers
- Performance optimization
- Risk: Medium | Priority: Medium

Phase 4: Stabilize (Months 16-18)
- Monitor and tune
- Documentation finalization
- Team training
- Risk: Low | Priority: Medium

Success Metrics:
- 99.9% uptime
- <200ms p95 latency
- 3x deployment frequency
- 50% reduction in incident response time"
```

**More examples**: [examples/](examples/)

---

## 📚 Documentation

### For Users
- **[Quick Start Guide](QUICKSTART.md)** - Get started in 5 minutes
- **[User Guide](docs/user-guide/)** - Comprehensive usage documentation
- **[Installation Guides](docs/installation/)** - Platform-specific installation
- **[Tutorials](docs/user-guide/tutorials/)** - Step-by-step learning paths
- **[Examples](examples/)** - Real-world use cases

### For Developers
- **[Contributing Guide](CONTRIBUTING.md)** - How to contribute
- **[API Reference](docs/reference/api-reference.md)** - Public API documentation
- **[Customization Guide](docs/advanced/customization.md)** - Extend Trinitas

### Reference
- **[Configuration](docs/reference/configuration.md)** - All configuration options
- **[FAQ](docs/reference/faq.md)** - Frequently asked questions
- **[Troubleshooting](docs/user-guide/troubleshooting.md)** - Common issues and solutions

---

## 🔧 Platform Support

| Platform | Status | Version | Guide |
|----------|--------|---------|-------|
| **Claude Code** | ✅ Fully Supported | 2.2.4 | [Installation](docs/installation/claude-code.md) |
| **OpenCode** | ✅ Fully Supported | 2.2.4 | [Installation](docs/installation/opencode.md) |
| **Linux** | ✅ Tested | Ubuntu 20.04+, Debian 11+ | [Guide](docs/installation/linux.md) |
| **macOS** | ✅ Tested | macOS 10.15+ | [Guide](docs/installation/macos.md) |
| **Windows** | ✅ Via WSL | WSL2 Ubuntu 20.04+ | [Guide](docs/installation/windows-wsl.md) |

---

## 🎯 Key Features

### File-Based Memory System
- **100% Local**: No external dependencies or API keys
- **Transparent**: Plain text files in `~/.claude/memory/`
- **Fast**: Instant access to previous decisions and patterns
- **Privacy-First**: All data stays on your machine

### Automatic Persona Detection
- **Keyword-Based**: Triggers like "optimize", "security", "architecture"
- **Context-Aware**: Understands multi-agent coordination requests
- **Explicit Override**: Specify persona when needed

### Built-In Security
- **Path Validation**: Prevents directory traversal (CWE-22)
- **Command Filtering**: Blocks dangerous operations
- **Rate Limiting**: Prevents abuse
- **Audit Trail**: Hestia logs all security-relevant actions

### Performance Optimization
- **97.6% Smaller Config**: Optimized from 44KB to 1.05KB
- **<100ms Load Time**: Fast startup and context loading
- **Minimal Memory**: Low resource footprint

---

## 🛠️ Advanced Features

### Multi-Agent Coordination Patterns

**Pattern 1: Parallel Analysis**
```
"Analyze this system" → Athena + Artemis + Hestia work in parallel
```

**Pattern 2: Sequential Workflow**
```
Athena (design) → Artemis (implement) → Hestia (audit) → Muses (document)
```

**Pattern 3: Consensus Building**
```
All personas review and reach agreement on critical decisions
```

**Learn more**: [docs/user-guide/usage-patterns.md](docs/user-guide/usage-patterns.md)

### MCP Tools Integration

Trinitas integrates with Model Context Protocol (MCP) tools:

- **File Operations**: Enhanced file management
- **Git Integration**: Version control automation
- **Database Tools**: Query optimization and analysis
- **Custom Tools**: Extend with your own MCP tools

**Guide**: [docs/advanced/mcp-integration.md](docs/advanced/mcp-integration.md)

---

## 🤝 Contributing

We welcome contributions from the community! Whether it's:

- 🐛 Bug reports
- 💡 Feature suggestions
- 📖 Documentation improvements
- 🔧 Code contributions

**Please see**: [CONTRIBUTING.md](CONTRIBUTING.md)

### Quick Contribution Guide

1. **Fork** the repository
2. **Create** a feature branch: `git checkout -b feature/my-feature`
3. **Make** your changes
4. **Test** thoroughly
5. **Submit** a Pull Request

---

## 🔒 Security

Security is a top priority. Hestia ensures:

- ✅ No dangerous commands execute without review
- ✅ All file operations validated
- ✅ Rate limiting prevents abuse
- ✅ Comprehensive audit logging

**Found a vulnerability?** See [SECURITY.md](SECURITY.md) for responsible disclosure.

---

## 📊 Project Status

- **Current Version**: 2.2.4 (Stable)
- **Release Date**: 2025-10-20
- **License**: MIT
- **Build Status**: ![Passing](https://img.shields.io/badge/build-passing-brightgreen)
- **Test Coverage**: ![85%](https://img.shields.io/badge/coverage-85%25-green)

**Changelog**: [CHANGELOG.md](CHANGELOG.md)

---

## 🎓 Learning Resources

### Tutorials
1. [Getting Started in 10 Minutes](docs/user-guide/tutorials/01-getting-started.md)
2. [Working with Multiple Personas](docs/user-guide/tutorials/02-multi-agent.md)
3. [Memory and Context Management](docs/user-guide/tutorials/03-memory-system.md)
4. [Advanced Customization](docs/user-guide/tutorials/04-customization.md)

### Use Cases
- [API Development Workflow](examples/real-world/api-development/)
- [Security Audit Process](examples/real-world/security-audit/)
- [Performance Optimization](examples/real-world/performance-optimization/)

---

## 💬 Community & Support

- **📖 Documentation**: [docs/](docs/)
- **🐛 Issues**: [GitHub Issues](https://github.com/apto-as/multi-agent-system/issues)
- **💡 Discussions**: [GitHub Discussions](https://github.com/apto-as/multi-agent-system/discussions)
- **📧 Email**: support@trinitas-project.example

---

## 📜 License

MIT License - See [LICENSE](LICENSE) for full text.

```
Copyright (c) 2025 Trinitas Project

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software...
```

---

## 🙏 Acknowledgments

- **Inspiration**: Greek and Roman mythology
- **Built for**: Claude Code and OpenCode platforms
- **Community**: Thank you to all contributors
- **Special Thanks**: Anthropic for Claude, SST for OpenCode

---

## 🗺️ Roadmap

### Current Focus (v2.2.x)
- ✅ File-based memory system
- ✅ Dual platform support (Claude Code + OpenCode)
- 🔄 Enhanced documentation
- 🔄 Community building

### Near Future (v2.3.x)
- 🔮 Multi-language support
- 🔮 Enhanced MCP tool integration
- 🔮 Performance dashboard
- 🔮 Plugin system for custom personas

### Long Term (v3.0.x)
- 🔮 Cloud sync option (opt-in)
- 🔮 Team collaboration features
- 🔮 Advanced analytics

**Vote on features**: [GitHub Discussions](https://github.com/apto-as/multi-agent-system/discussions/categories/ideas)

---

## 📈 Stats

- **⭐ Stars**: [GitHub stars]
- **🍴 Forks**: [GitHub forks]
- **👥 Contributors**: [GitHub contributors]
- **📦 Installations**: [Download count]
- **🐛 Open Issues**: [GitHub open issues]

---

## Persona Messages

> **Athena**: "ふふ、素晴らしいシステムですね。調和的な協力で最高の成果を♪"
>
> **Artemis**: "フン、この最適化なら私の基準を満たすわ。完璧を目指しましょう。"
>
> **Hestia**: "...セキュリティ監視中...すべての脅威から守ります..."
>
> **Eris**: "戦術的調整を開始。チーム全体の効率を最大化します。"
>
> **Hera**: "戦略分析完了。成功確率: 98.7%。実行を承認。"
>
> **Muses**: "...知識を構造化し、永続的に保存します..."

---

<div align="center">

**[Get Started](INSTALLATION.md)** | **[Documentation](docs/)** | **[Examples](examples/)** | **[Contribute](CONTRIBUTING.md)**

*Trinitas v2.2.4 - Six Minds, Unified Intelligence*

</div>
