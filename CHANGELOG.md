# Changelog

All notable changes to TMWS (Trinitas Memory & Workflow Service) will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed - 2025-10-01

#### CI/CDパイプライン最適化

**変更内容:**
- GitHub Actions workflowからDocker build jobを削除
- 3つのジョブ構成に簡素化: test, security, notify
- テスト実行時間の短縮（Docker buildステップ削除により約3-5分短縮）

**理由:**
- TMWSは現在Dockerfileを持たず、直接Pythonプロセスとして実行される設計
- 存在しないDockerfileのビルドによる誤った失敗を排除
- CI/CDパイプラインの信頼性向上と実行速度の改善

**技術的影響:**
- テストジョブ: PostgreSQL + pgvector, Redisサービスを使用した統合テスト実行
- セキュリティジョブ: Bandit, Safety, pip-auditによる脆弱性スキャン（継続実施）
- 通知ジョブ: パイプライン全体のステータス集約と報告

**今後の展開:**
- Dockerfile実装時には専用のデプロイメントガイド参照
- コンテナ化が必要な場合のドキュメント整備完了

**関連ドキュメント:**
- CI/CD設定: `.github/workflows/test-suite.yml`
- 将来のDocker実装: `docs/dev/FUTURE_DOCKER_IMPLEMENTATION.md`
- セキュリティ改善計画: `docs/security/SECURITY_IMPROVEMENT_ROADMAP.md`

**担当ペルソナ:**
- Artemis: ワークフロー最適化実施
- Hestia: セキュリティ監査と条件付き承認
- Eris: チーム調整と最終検証
- Muses: ドキュメント作成

## [1.0.0] - 2025-01-09

### 🎉 First Stable Release

TMWS v1.0.0 marks the first stable release of the Universal Agent Memory System with full MCP (Model Context Protocol) support for Claude Code integration.

### ✨ Features

- **Universal Agent System**: Support for any AI agent, not limited to specific implementations
- **MCP Protocol Support**: Full integration with Claude Code via Model Context Protocol
- **PostgreSQL + pgvector**: Robust database backend with vector similarity search
- **Semantic Memory**: Intelligent memory storage and retrieval using embeddings
- **Multi-Agent Management**: Pre-configured with 6 Trinitas agents (Athena, Artemis, Hestia, Eris, Hera, Muses)
- **Custom Agent Registration**: Dynamic registration of custom agents via MCP tools
- **Task & Workflow Management**: Complete task tracking and workflow orchestration
- **Environment Configuration**: Flexible configuration via .env files
- **Security**: Agent authentication, access control, and audit logging

### 🛠️ Technical Improvements

- **Database Architecture**: Proper model registration with SQLAlchemy 2.0
- **Async Support**: Full async/await implementation for better performance
- **Error Handling**: Comprehensive error handling and logging
- **Pydantic V2**: Migration to Pydantic V2 for better validation
- **FastMCP Integration**: Seamless MCP server implementation

### 📚 Documentation

- Complete PostgreSQL setup instructions
- Environment configuration guide
- Claude Code integration documentation
- Custom agent registration guide
- Database setup script for easy initialization

### 🔧 Requirements

- Python 3.11+
- PostgreSQL 14+ with pgvector and pg_trgm extensions
- Claude Code for MCP integration

### 🙏 Acknowledgments

This release represents a complete rewrite from the persona-specific system to a universal multi-agent platform, enabling any AI agent to leverage persistent memory and semantic search capabilities.

---

[1.0.0]: https://github.com/apto-as/tmws/releases/tag/v1.0.0