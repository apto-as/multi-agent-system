# TMWS Deployment Documentation
## Comprehensive Deployment Guides for All Environments

**Last Updated**: 2025-11-16
**Status**: Complete Documentation Structure

---

## 📚 Documentation Organization

This directory contains deployment guides for TMWS across various environments and deployment modes. Documents are organized by deployment phase and complexity level.

---

## 🗂️ Documentation Structure

### Phase 2C (RBAC + License MCP) - v2.3.0

**Production Deployment**:
- **[PHASE_2C_PRODUCTION_DEPLOYMENT.md](PHASE_2C_PRODUCTION_DEPLOYMENT.md)** - Complete production deployment guide for v2.3.0
  - Infrastructure setup (PostgreSQL, Redis, ChromaDB)
  - Multi-agent architecture configuration
  - Security hardening (HTTPS, secrets management)
  - Monitoring and alerting setup

**Operational Procedures**:
- **[RBAC_ROLLBACK_PROCEDURE.md](RBAC_ROLLBACK_PROCEDURE.md)** - Emergency rollback procedures
  - Rollback triggers and decision criteria
  - Step-by-step rollback instructions
  - Data preservation strategies
  - Post-rollback verification

- **[MONITORING_CHECKLIST.md](MONITORING_CHECKLIST.md)** - Post-deployment monitoring
  - Health check procedures
  - Performance metrics (P95 latency targets)
  - Security monitoring (audit logs, failed auth attempts)
  - Alert configuration

**Legacy Deployment**:
- **[MCP_API_DEPLOYMENT.md](MCP_API_DEPLOYMENT.md)** - Dual-mode deployment (MCP + REST API)
  - Note: REST API deprecated in v2.3.1+ (MCP-only architecture)

---

### Phase 2D (Docker Deployment) - v2.3.1

**Docker Deployment**:
- **[DOCKER_DEPLOYMENT.md](DOCKER_DEPLOYMENT.md)** - Docker deployment guide (all platforms)
  - Deployment modes: Mac Hybrid, Windows/Linux Hybrid, Full Docker
  - Quick Start (30 seconds to production)
  - Platform-specific configurations
  - Production security hardening
  - Troubleshooting and maintenance

**MCP Integration**:
- **[MCP_CONNECTION_DOCKER.md](MCP_CONNECTION_DOCKER.md)** - Claude Desktop + Docker integration
  - Wrapper script creation (Mac, Windows, Linux)
  - Claude Desktop configuration
  - Multi-agent setup (namespace isolation)
  - Connection troubleshooting

**Future Documentation** (Planned for v2.3.2+):
- `DOCKER_TROUBLESHOOTING.md` - Common Docker issues and solutions
- `KUBERNETES_DEPLOYMENT.md` - Kubernetes deployment for cloud-native architectures
- `CLOUD_DEPLOYMENT_AWS.md` - AWS-specific deployment (ECS, EKS)
- `CLOUD_DEPLOYMENT_GCP.md` - Google Cloud Platform deployment
- `CLOUD_DEPLOYMENT_AZURE.md` - Azure deployment

---

## 🚀 Quick Navigation

### I'm a new user - where do I start?

**Local Development (Beginner)**:
1. Start with [../DEVELOPMENT_SETUP.md](../DEVELOPMENT_SETUP.md) - Native installation
2. Then [../MCP_INTEGRATION.md](../MCP_INTEGRATION.md) - Claude Desktop setup

**Docker Deployment (Recommended)**:
1. [DOCKER_DEPLOYMENT.md](DOCKER_DEPLOYMENT.md) → Section 3 (Quick Start)
2. [MCP_CONNECTION_DOCKER.md](MCP_CONNECTION_DOCKER.md) → Section 3 (Setup Instructions)

**Production Deployment**:
1. [DOCKER_DEPLOYMENT.md](DOCKER_DEPLOYMENT.md) → Section 6 (Production Deployment)
2. [MONITORING_CHECKLIST.md](MONITORING_CHECKLIST.md) - Post-deployment monitoring
3. [RBAC_ROLLBACK_PROCEDURE.md](RBAC_ROLLBACK_PROCEDURE.md) - Keep handy for emergencies

---

### I'm troubleshooting an issue - help!

**Docker Connection Issues**:
→ [MCP_CONNECTION_DOCKER.md](MCP_CONNECTION_DOCKER.md) → Section 7 (Troubleshooting)

**Docker Container Won't Start**:
→ [DOCKER_DEPLOYMENT.md](DOCKER_DEPLOYMENT.md) → Section 8.1 (Container Won't Start)

**Ollama Connection Failures**:
→ [DOCKER_DEPLOYMENT.md](DOCKER_DEPLOYMENT.md) → Section 8.2 (Ollama Connection Issues)

**Performance Problems**:
→ [DOCKER_DEPLOYMENT.md](DOCKER_DEPLOYMENT.md) → Section 8.3 (Performance Issues)
→ [MONITORING_CHECKLIST.md](MONITORING_CHECKLIST.md) → Performance Metrics

**RBAC Permission Errors**:
→ [RBAC_ROLLBACK_PROCEDURE.md](RBAC_ROLLBACK_PROCEDURE.md) → Emergency Access

**Production Incident**:
→ [RBAC_ROLLBACK_PROCEDURE.md](RBAC_ROLLBACK_PROCEDURE.md) → Rollback Procedures
→ [MONITORING_CHECKLIST.md](MONITORING_CHECKLIST.md) → Health Checks

---

### I'm migrating from an older version

**v2.2.x → v2.3.0 (RBAC + License)**:
→ [PHASE_2C_PRODUCTION_DEPLOYMENT.md](PHASE_2C_PRODUCTION_DEPLOYMENT.md) → Migration Section

**Native Installation → Docker**:
→ [DOCKER_DEPLOYMENT.md](DOCKER_DEPLOYMENT.md) → Section 10.1 (Migrating from Native Installation)

**Hybrid → Full Docker** (or vice versa):
→ [DOCKER_DEPLOYMENT.md](DOCKER_DEPLOYMENT.md) → Section 10.2 (Migrating Between Deployment Modes)

**Cross-Platform Migration** (Mac → Linux, etc.):
→ [DOCKER_DEPLOYMENT.md](DOCKER_DEPLOYMENT.md) → Section 10.3 (Platform Migration)

---

## 📖 Reading Guide by User Type

### DevOps Engineers / System Administrators

**Recommended Reading Order**:
1. [DOCKER_DEPLOYMENT.md](DOCKER_DEPLOYMENT.md) - Complete Docker deployment
   - Section 2: Prerequisites (system requirements, software dependencies)
   - Section 6: Production Deployment (pre-deployment checklist, security)
   - Section 7: Security Hardening (network, HTTPS, access control)
   - Section 9: Maintenance (updates, monitoring, backups)

2. [MONITORING_CHECKLIST.md](MONITORING_CHECKLIST.md) - Post-deployment monitoring
   - Performance metrics (P95 latency targets)
   - Security monitoring (audit logs, alert configuration)
   - Health checks (database, ChromaDB, Ollama)

3. [RBAC_ROLLBACK_PROCEDURE.md](RBAC_ROLLBACK_PROCEDURE.md) - Emergency procedures
   - Keep handy for production incidents

**Optional (for native deployment)**:
- [PHASE_2C_PRODUCTION_DEPLOYMENT.md](PHASE_2C_PRODUCTION_DEPLOYMENT.md) - PostgreSQL-based deployment (legacy)

---

### End Users / AI Researchers

**Recommended Reading Order**:
1. [DOCKER_DEPLOYMENT.md](DOCKER_DEPLOYMENT.md) - Quick Start section
   - Section 3.1 (Mac Hybrid) or 3.2 (Windows/Linux Hybrid)
   - 30-second setup to get TMWS running

2. [MCP_CONNECTION_DOCKER.md](MCP_CONNECTION_DOCKER.md) - Claude Desktop integration
   - Section 3: Setup Instructions (wrapper scripts)
   - Section 4: Platform-Specific Guides (Mac, Windows, Linux)
   - Section 5: Verification (test connection)

**Optional (for advanced users)**:
- Section 8: Multi-Agent Setup (namespace isolation)
- [MONITORING_CHECKLIST.md](MONITORING_CHECKLIST.md) - Monitor your deployment

---

### Developers

**Recommended Reading Order**:
1. [../DEVELOPMENT_SETUP.md](../DEVELOPMENT_SETUP.md) - Local development environment
2. [DOCKER_DEPLOYMENT.md](DOCKER_DEPLOYMENT.md) - Docker deployment for testing
   - Section 4.3 (Full Docker) - Complete environment isolation
3. [MCP_CONNECTION_DOCKER.md](MCP_CONNECTION_DOCKER.md) - MCP integration
4. [../MCP_INTEGRATION.md](../MCP_INTEGRATION.md) - MCP protocol details

**Optional (for production deployment)**:
- [PHASE_2C_PRODUCTION_DEPLOYMENT.md](PHASE_2C_PRODUCTION_DEPLOYMENT.md) - Production architecture

---

## 🎯 Deployment Decision Matrix

| Scenario | Recommended Deployment | Documentation |
|----------|----------------------|---------------|
| **Local Development** | Native installation (Python 3.11+, uv) | [../DEVELOPMENT_SETUP.md](../DEVELOPMENT_SETUP.md) |
| **Mac User (M1/M2/M3/M4)** | Mac Hybrid (Ollama native + TMWS Docker) | [DOCKER_DEPLOYMENT.md](DOCKER_DEPLOYMENT.md) Section 4.1 |
| **Windows/Linux Production** | Windows/Linux Hybrid (Ollama native + TMWS Docker) | [DOCKER_DEPLOYMENT.md](DOCKER_DEPLOYMENT.md) Section 4.2 |
| **Complete Isolation** | Full Docker (Ollama + TMWS in containers) | [DOCKER_DEPLOYMENT.md](DOCKER_DEPLOYMENT.md) Section 4.3 |
| **CI/CD Testing** | Full Docker (reproducible environments) | [DOCKER_DEPLOYMENT.md](DOCKER_DEPLOYMENT.md) Section 4.3 |
| **Multi-Tenant SaaS** | Kubernetes (future) | Planned: `KUBERNETES_DEPLOYMENT.md` |
| **Cloud Native (AWS)** | ECS/EKS (future) | Planned: `CLOUD_DEPLOYMENT_AWS.md` |

---

## 🔧 Deployment Architecture Comparison

### Mac Hybrid (Recommended for Mac)
```
macOS Host
├─ Ollama (Native, Metal GPU)  ⚡ 3-5x faster embeddings
└─ TMWS (Docker Container)
```
**Pros**: Maximum GPU performance, simple setup, fast model loading
**Cons**: Mac-specific, Ollama managed separately

---

### Windows/Linux Hybrid (Recommended for Production)
```
Host OS
├─ Ollama (Native, CUDA GPU)  ⚡ 2-4x faster embeddings
└─ TMWS (Docker Container)
```
**Pros**: Production-ready, GPU acceleration, fast updates
**Cons**: Platform-specific network configuration

---

### Full Docker (Maximum Isolation)
```
Docker Environment
├─ Ollama (Docker Container, GPU passthrough)
└─ TMWS (Docker Container)
```
**Pros**: Complete isolation, reproducible, CI/CD-friendly
**Cons**: Complex GPU setup, higher resource overhead

---

### Native Installation (Legacy)
```
Host OS
├─ Python 3.11+ (uv virtual environment)
├─ PostgreSQL 17 (optional, SQLite default)
├─ Ollama (Native)
└─ TMWS (Python application)
```
**Pros**: Maximum control, easy debugging
**Cons**: Dependency management, platform-specific issues

---

## 📊 Performance Benchmarks (Docker vs Native)

| Metric | Native | Docker (Mac Hybrid) | Docker (Full) | Target |
|--------|--------|---------------------|---------------|--------|
| **Memory Creation** | 4ms | 8ms | 10ms | <10ms |
| **Semantic Search** | 12ms | 15ms | 20ms | <20ms |
| **Vector Embedding** (GPU) | 40ms | 50ms | 70ms | <100ms |
| **Vector Embedding** (CPU) | 180ms | 200ms | 250ms | <300ms |
| **Container Overhead** | N/A | ~2-3ms | ~5-7ms | <10ms |

**Conclusion**: Docker deployment adds minimal overhead (<10ms P95), well within target latency.

---

## 🛡️ Security Considerations

### Development vs Production Security

| Configuration | Development | Production |
|---------------|-------------|------------|
| **TMWS_AUTH_ENABLED** | `false` | `true` ✅ |
| **TMWS_SECRET_KEY** | Default | Unique 64-char hex ✅ |
| **CORS_ORIGINS** | `["*"]` | Specific domains ✅ |
| **HTTPS** | Optional | Required ✅ |
| **Database Encryption** | Optional | Recommended ✅ |
| **Audit Logging** | Minimal | Comprehensive ✅ |

**Security Checklist**:
- [ ] SECRET_KEY generated with `openssl rand -hex 32` (never reuse)
- [ ] .env file in .gitignore (never commit secrets)
- [ ] CORS restricted to production domains only
- [ ] HTTPS configured for internet-facing deployments
- [ ] Monitoring and alerting configured (see [MONITORING_CHECKLIST.md](MONITORING_CHECKLIST.md))

---

## 🆘 Emergency Procedures

### Production Incident Response

**Step 1: Assess Severity**
- **Critical** (service down, data loss): Immediate rollback → [RBAC_ROLLBACK_PROCEDURE.md](RBAC_ROLLBACK_PROCEDURE.md)
- **High** (performance degradation): Check monitoring → [MONITORING_CHECKLIST.md](MONITORING_CHECKLIST.md)
- **Medium** (isolated issues): Troubleshooting → [DOCKER_DEPLOYMENT.md](DOCKER_DEPLOYMENT.md) Section 8

**Step 2: Execute Recovery**
- Follow emergency procedures in RBAC_ROLLBACK_PROCEDURE.md
- Document incident in post-mortem (see template in RBAC_ROLLBACK_PROCEDURE.md)

**Step 3: Post-Incident**
- Review monitoring data
- Update deployment procedures if needed
- Communicate resolution to stakeholders

---

## 📝 Contributing to Documentation

### Documentation Standards

**Style Guide**:
- **Headers**: Use sentence case (e.g., "Quick start" not "Quick Start")
- **Code blocks**: Always specify language for syntax highlighting
- **Paths**: Use absolute paths in examples (not ~/  or %USERPROFILE%)
- **Platform-specific**: Clearly label Mac, Windows, Linux sections
- **Commands**: Test on all platforms before committing

**Documentation Structure**:
1. **Overview** - What this document covers (and doesn't cover)
2. **Prerequisites** - What user needs before starting
3. **Step-by-step instructions** - Clear, tested procedures
4. **Verification** - How to confirm success
5. **Troubleshooting** - Common issues and solutions
6. **Related documentation** - Links to related guides

**Review Checklist**:
- [ ] Tested on target platform (Mac/Windows/Linux)
- [ ] All commands execute successfully
- [ ] Screenshots/diagrams up to date (if applicable)
- [ ] Links to related docs valid
- [ ] TOC updated (if structure changed)
- [ ] Last Updated date changed
- [ ] Version number updated

---

## 🔗 Related Documentation

### Architecture
- [../architecture/TMWS_v2.2.0_ARCHITECTURE.md](../architecture/TMWS_v2.2.0_ARCHITECTURE.md) - System architecture overview
- [../architecture/AGENT_TRUST_VERIFICATION_ARCHITECTURE.md](../architecture/AGENT_TRUST_VERIFICATION_ARCHITECTURE.md) - Trust system architecture

### Development
- [../DEVELOPMENT_SETUP.md](../DEVELOPMENT_SETUP.md) - Local development environment
- [../dev/EXCEPTION_HANDLING_GUIDELINES.md](../dev/EXCEPTION_HANDLING_GUIDELINES.md) - Exception handling patterns
- [../dev/COMMIT_GUIDELINES.md](../dev/COMMIT_GUIDELINES.md) - Commit message conventions

### Guides
- [../guides/MCP_SETUP_GUIDE.md](../guides/MCP_SETUP_GUIDE.md) - MCP protocol setup
- [../guides/CUSTOM_AGENTS_GUIDE.md](../guides/CUSTOM_AGENTS_GUIDE.md) - Custom agent creation
- [../guides/NAMESPACE_DETECTION_GUIDE.md](../guides/NAMESPACE_DETECTION_GUIDE.md) - Namespace isolation

### Security
- [../security/SECURITY_IMPROVEMENT_ROADMAP.md](../security/SECURITY_IMPROVEMENT_ROADMAP.md) - Security enhancements
- [../API_AUTHENTICATION.md](../API_AUTHENTICATION.md) - Authentication mechanisms

---

## 📞 Support Channels

**GitHub Issues**: https://github.com/apto-as/tmws/issues
- Bug reports, feature requests

**GitHub Discussions**: https://github.com/apto-as/tmws/discussions
- Deployment questions, architecture discussions

**Email**: security@apto-as.com
- Security vulnerabilities (responsible disclosure)

---

## 📅 Documentation Roadmap

### Completed (v2.3.1)
- ✅ DOCKER_DEPLOYMENT.md - Complete Docker deployment guide
- ✅ MCP_CONNECTION_DOCKER.md - Claude Desktop + Docker integration
- ✅ README.md - This document (deployment documentation index)

### Planned (v2.3.2)
- 📝 DOCKER_TROUBLESHOOTING.md - Extended troubleshooting guide
- 📝 KUBERNETES_DEPLOYMENT.md - K8s deployment for cloud-native
- 📝 CLOUD_DEPLOYMENT_AWS.md - AWS-specific deployment (ECS/EKS)

### Future (v2.4.0+)
- 📝 CLOUD_DEPLOYMENT_GCP.md - Google Cloud Platform deployment
- 📝 CLOUD_DEPLOYMENT_AZURE.md - Azure deployment
- 📝 MULTI_REGION_DEPLOYMENT.md - Multi-region architecture
- 📝 DISASTER_RECOVERY_GUIDE.md - DR procedures and RTO/RPO targets

---

**Last Updated**: 2025-11-16
**Next Review**: 2025-12-16
**Maintained By**: Muses (Knowledge Architect) + Trinitas Team
**Status**: Production-Ready ✅
