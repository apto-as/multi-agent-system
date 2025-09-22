# Claude Code Setup for TMWS v2.2.0

## 正しい接続方法

### 方法1: stdio MCPで直接接続（推奨）
各Claude Codeインスタンスが独自のstdio MCPプロセスを起動し、共有サーバーに接続：

```json
{
  "mcpServers": {
    "tmws": {
      "command": "uvx",
      "args": ["--from", "git+https://github.com/apto-as/tmws", "tmws"],
      "env": {
        "TMWS_DATABASE_URL": "postgresql://user:pass@shared-server:5432/tmws",
        "TMWS_AGENT_ID": "unique-agent-id-1"
      }
    }
  }
}
```

### 方法2: ローカルインストールで接続
```json
{
  "mcpServers": {
    "tmws": {
      "command": "python",
      "args": ["-m", "src.mcp_server"],
      "env": {
        "TMWS_DATABASE_URL": "postgresql://user:pass@shared-server:5432/tmws",
        "TMWS_AGENT_ID": "unique-agent-id-2"
      }
    }
  }
}
```

## なぜこの設計なのか

1. **MCP標準準拠**: Claude CodeはMCPプロトコル（stdio JSON-RPC）を期待
2. **データベース共有**: 各MCPクライアントは同じPostgreSQLデータベースに接続
3. **エージェント分離**: TMWS_AGENT_IDで各クライアントを識別

## 共有サーバーアーキテクチャ

```
[Claude Code 1] --stdio--> [MCP Process 1] --SQL--> [PostgreSQL]
[Claude Code 2] --stdio--> [MCP Process 2] --SQL--> [PostgreSQL]
[Claude Code 3] --stdio--> [MCP Process 3] --SQL--> [PostgreSQL]
                                                          ^
                                                          |
                                                   [Shared Database]
```

## WebSocket MCPの誤解について

WebSocket MCPは将来の拡張のために実装しましたが、現在のClaude Codeは：
- stdio（標準入出力）経由のJSON-RPCのみサポート
- WebSocket接続を直接サポートしていない

そのため、複数のClaude Codeインスタンスは：
1. それぞれ独自のMCPプロセスを起動
2. 同じデータベースに接続して情報を共有
3. TMWS_AGENT_IDで識別される

これが正しい設計です。